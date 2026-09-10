package jinguissl.contract

import std.collection.ArrayList
import std.sync.Mutex
import jinguissl_core.crypto.compliance.TlsVersion
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.tls.{
    Tls13RecordLayerHandle, TlsAeadAlgorithm, TlsAeadRecordLayer,
    TlsChacha20Poly1305RecordLayer, TlsContentType, tlsDecodeRecord, tlsEncodeRecord
}

/** Bounded TLS 1.3 byte-stream client adapter; owns separate handshake/application
 * record counters. Caller owns the socket, deadlines and transmission ordering.
 * Call takeHandshakeOutput() initially and after receive(); send handshake/close bytes in
 * order before sending application data. No HTTP policy, QUIC packets or 0-RTT.
 * close/failure revokes access and releases contexts; legacy Core record contexts
 * do not yet promise explicit key-schedule erasure. */
public class ContractTls13StreamClient {
    private let mutex = Mutex()
    private let engine: ContractTls13ClientEngine
    private var pending: Array<Byte> = []
    private var outbound: Array<Byte>
    private var handshake: ?Tls13RecordLayerHandle = None
    private var application: ?Tls13RecordLayerHandle = None
    private var closed: Bool = false
    private var handshakeRecords: Int64 = 0

    public init(
        trustAnchorsPem: String, hostname: String, validationTime: String,
        alpnProtocols!: Array<String> = [], requireAlpn!: Bool = false,
        cipherSuites!: Array<Int64> = [0x1301, 0x1302, 0x1303]
    ) {
        this.engine = ContractTls13ClientEngine(
            trustAnchorsPem, hostname, validationTime, alpnProtocols: alpnProtocols,
            requireAlpn: requireAlpn, cipherSuites: cipherSuites
        )
        this.outbound = tlsEncodeRecord(TlsContentType.Handshake, TlsVersion.TLS1_2, engine.clientHello())
    }

    public prop authenticated: Bool { get() { synchronized(mutex) { !closed && engine.authenticated } } }
    public prop isClosed: Bool { get() { synchronized(mutex) { closed } } }
    public func selectedAlpn(): String { synchronized(mutex) { requireOpen(); engine.selectedAlpn() } }
    public func peerCertificateChainDer(): Array<Array<Byte>> {
        synchronized(mutex) { requireOpen(); engine.peerCertificateChainDer() }
    }
    public func takeHandshakeOutput(): Array<Byte> {
        synchronized(mutex) {
            if (closed && outbound.size == 0) { requireOpen() }
            let result = outbound.clone()
            outbound = []
            result
        }
    }

    /** Feed ordered wire bytes; returns authenticated application-data fragments.
     * Never returns protected handshake plaintext or keys to the application. */
    public func receive(bytes: Array<Byte>): Array<Array<Byte>> {
        synchronized(mutex) {
            requireOpen()
            try {
                if (bytes.size > 1048576 || pending.size > 16645) { throw streamError("wire input exceeds bounded budget") }
                pending = streamJoin([pending, bytes])
                let data = ArrayList<Array<Byte>>()
                var offset: Int64 = 0
                while (pending.size - offset >= 5) {
                    let kind = pending[offset]
                    if (pending[offset + 1] != 3 || pending[offset + 2] != 3) {
                        throw streamError("TLS 1.3 peer record version must be 0x0303")
                    }
                    let length = (Int64(pending[offset + 3]) << 8) | Int64(pending[offset + 4])
                    if (length > 16640 || (kind == 22 && length > 16384)) {
                        throw streamError("TLS record exceeds protocol size limit")
                    }
                    if (pending.size - offset < 5 + length) { break }
                    let record = pending[offset..(offset + 5 + length)].clone()
                    offset += 5 + length
                    if (!engine.authenticated) {
                        handshakeRecords += 1
                        if (handshakeRecords > 4096) { throw streamError("handshake record budget exceeded") }
                    }
                    if (kind == 20) {
                        // Compatibility CCS is ignored only between ClientHello and Finished.
                        if (engine.authenticated || length != 1 || record[5] != 1) {
                            throw streamError("unexpected ChangeCipherSpec")
                        }
                        continue
                    }
                    if (kind == 22 && handshake.isNone()) {
                        engine.receiveInitial(tlsDecodeRecord(record).fragment)
                        if (engine.cipherSuite != 0) {
                            let secrets = engine.handshakeSecrets()
                            try { handshake = Some(streamLayer(secrets)) } finally { secrets.destroy() }
                        }
                    } else if (kind == 23) {
                        if (engine.authenticated) {
                            match (application) {
                                case Some(layer) =>
                                    let plain = layer.open(record)
                                    if (plain.contentType == TlsContentType.Handshake) {
                                        engine.receivePostHandshake(plain.fragment)
                                    } else if (plain.contentType == TlsContentType.Alert) {
                                        if (plain.fragment.size != 2 || plain.fragment[1] != 0 ||
                                            (plain.fragment[0] != 1 && plain.fragment[0] != 2)) {
                                            throw streamError("TLS peer fatal alert")
                                        }
                                        if (offset != pending.size) { throw streamError("TLS records after close_notify") }
                                        let reply = layer.seal(TlsContentType.Alert, [UInt8(1), UInt8(0)])
                                        closeOwned()
                                        outbound = reply
                                        return data.toArray()
                                    } else if (plain.contentType == TlsContentType.ApplicationData) {
                                        data.add(plain.fragment.clone())
                                    } else {
                                        throw streamError("unexpected protected record content type")
                                    }
                                case None => throw streamError("application record state is unavailable")
                            }
                        } else {
                            match (handshake) {
                                case Some(layer) =>
                                    let plain = layer.open(record)
                                    if (plain.contentType != TlsContentType.Handshake) {
                                        throw streamError("application data or alert before server authentication")
                                    }
                                    engine.receiveHandshake(plain.fragment)
                                    if (engine.authenticated) {
                                        outbound = streamJoin([outbound, layer.seal(TlsContentType.Handshake, engine.clientFinished())])
                                        let secrets = engine.applicationSecrets()
                                        try { application = Some(streamLayer(secrets)) } finally { secrets.destroy() }
                                        handshake = None
                                    }
                                case None => throw streamError("protected record before ServerHello")
                            }
                        }
                    } else {
                        throw streamError("unexpected TLS record content type or encryption level")
                    }
                }
                pending = pending[offset..].clone()
                data.toArray()
            } catch (e: CryptoException) {
                closeOwned()
                throw ContractException(ContractErrorCode.VerifyFailed, "TLS record rejected: ${e.message}")
            } catch (e: ContractException) {
                closeOwned()
                throw e
            }
        }
    }

    public func sealApplicationData(bytes: Array<Byte>): Array<Byte> {
        synchronized(mutex) {
            requireOpen()
            if (!engine.authenticated || outbound.size != 0) {
                throw streamError("authenticate and drain client Finished before application writes")
            }
            if (bytes.size > 16384) { throw streamError("split application writes into at most 16 KiB") }
            try {
                match (application) {
                    case Some(layer) => layer.seal(TlsContentType.ApplicationData, bytes)
                    case None => throw streamError("application record state is unavailable")
                }
            } catch (e: CryptoException) {
                closeOwned()
                throw ContractException(ContractErrorCode.CryptoUnavailable, "TLS record seal failed: ${e.message}")
            }
        }
    }
    public func close(): Unit { synchronized(mutex) { closeOwned() } }
    /** Emit one protected close_notify and retire the local connection state. */
    public func closeNotify(): Array<Byte> {
        synchronized(mutex) {
            requireOpen()
            if (!engine.authenticated || outbound.size != 0) { throw streamError("drain handshake before close_notify") }
            try {
                match (application) {
                    case Some(layer) => layer.seal(TlsContentType.Alert, [UInt8(1), UInt8(0)])
                    case None => throw streamError("application record state is unavailable")
                }
            } catch (e: CryptoException) {
                throw ContractException(ContractErrorCode.CryptoUnavailable, "TLS close notification failed: ${e.message}")
            } finally { closeOwned() }
        }
    }
    private func requireOpen(): Unit { if (closed) { throw streamError("TLS stream client is closed") } }
    private func closeOwned(): Unit {
        engine.close()
        handshake = None
        application = None
        pending = []
        outbound = []
        closed = true
    }
}

private func streamLayer(secrets: ContractTls13PhaseSecrets): Tls13RecordLayerHandle {
    let (writeKey, writeIv) = secrets.clientTlsKeyIv()
    let (readKey, readIv) = secrets.serverTlsKeyIv()
    try {
        if (secrets.cipherSuite == 0x1303) {
            Tls13RecordLayerHandle(TlsAeadAlgorithm.CHACHA20_POLY1305,
                chachaLayer: Some(TlsChacha20Poly1305RecordLayer(writeKey, writeIv,
                    readKey: readKey, readIv: readIv, version: TlsVersion.TLS1_3)))
        } else {
            Tls13RecordLayerHandle(TlsAeadAlgorithm.AES_GCM,
                aesLayer: Some(TlsAeadRecordLayer(writeKey, writeIv,
                    readKey: readKey, readIv: readIv, version: TlsVersion.TLS1_3)))
        }
    } finally {
        for (i in 0..writeKey.size) { writeKey[i] = 0 }
        for (i in 0..readKey.size) { readKey[i] = 0 }
    }
}
private func streamError(message: String): ContractException { ContractException(ContractErrorCode.BadInput, message) }
private func streamJoin(parts: Array<Array<Byte>>): Array<Byte> {
    let out = ArrayList<Byte>()
    for (part in parts) { for (b in part) { out.add(b) } }
    out.toArray()
}
