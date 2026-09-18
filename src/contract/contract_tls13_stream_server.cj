package jinguissl.contract

import std.collection.ArrayList
import jinguissl_core.crypto.compliance.TlsVersion
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.digest.{sha256, sha384}
import jinguissl_core.crypto.ecc.{EcPrivateKey, NamedCurve, ecPublicFromPrivateKey}
import jinguissl_core.crypto.tls.*
import jinguissl_core.crypto.utils.constantTimeEquals
import jinguissl_core.crypto.x25519.{x25519GeneratePrivateKey, x25519PublicFromPrivate}
import jinguissl_core.crypto.x509.{x509ParsePemChain, x509ParseEcPrivateKeyPkcs8Pem, x509ExtractEcPublicKey}

/// Application-independent TLS 1.3 server over caller-owned ordered bytes.
/// P-256 certificate, X25519 exchange, 0x1301/02/03. No HTTP defaults, client
/// identity authentication, HRR, PSK, early data, resumption or KeyUpdate.
/// Caller serializes calls, enforces deadlines and transmits queued bytes in order.
public class ContractTls13StreamServer {
    private let chain: Array<Array<Byte>>
    private var signer: ?EcPrivateKey
    private let alpn: Array<String>
    private let requireAlpn: Bool
    private var pending: Array<Byte> = []
    private var hello: Array<Byte> = []
    private var finished: Array<Byte> = []
    private var expectedFinished: Array<Byte> = []
    private var outbound: Array<Byte> = []
    private var handshake: ?Tls13RecordLayerHandle = None
    private var application: ?Tls13RecordLayerHandle = None
    private var closed: Bool = false
    private var ready: Bool = false
    private var selected: String = ""
    private var suite: Int64 = 0
    private var recordCount: Int64 = 0

    public init(certificateChainPem: String, ecPrivateKeyPkcs8Pem: String,
        alpnProtocols!: Array<String> = [], requireAlpn!: Bool = false) {
        if (requireAlpn && alpnProtocols.size == 0) { throw serverStreamError("ALPN preference is required") }
        for (name in alpnProtocols) {
            if (name.size == 0 || name.size > 255 || name.trimAscii() != name) {
                throw serverStreamError("invalid ALPN identifier")
            }
        }
        this.alpn = alpnProtocols.clone()
        this.requireAlpn = requireAlpn
        try {
            let certs = x509ParsePemChain(certificateChainPem)
            if (certs.size == 0 || certs.size > 16) { throw serverStreamError("invalid certificate chain size") }
            let key = x509ParseEcPrivateKeyPkcs8Pem(ecPrivateKeyPkcs8Pem)
            let derived = ecPublicFromPrivateKey(key)
            let supplied = x509ExtractEcPublicKey(certs[0])
            if (key.curve != NamedCurve.P256 || supplied.curve != key.curve ||
                derived.x.cmp(supplied.x) != 0 || derived.y.cmp(supplied.y) != 0) {
                throw serverStreamError("server P-256 private key does not match leaf certificate")
            }
            this.chain = Array<Array<Byte>>(certs.size, {i => certs[i].der.clone()})
            this.signer = Some(key)
        } catch (e: CryptoException) { throw serverStreamError(e.message) }
    }

    /// Client Finished verified; this is NOT client certificate authentication.
    public prop established: Bool { get() { ready && !closed } }
    public prop isClosed: Bool { get() { closed } }
    public prop cipherSuite: Int64 { get() { suite } }
    public func selectedAlpn(): String { requireOpen(); selected }
    public func takeHandshakeOutput(): Array<Byte> {
        if (closed && outbound.size == 0) { requireOpen() }
        let bytes = outbound
        outbound = []
        bytes
    }

    public func receive(bytes: Array<Byte>): Array<Array<Byte>> {
        requireOpen()
        try {
            if (bytes.size > 1048576 || pending.size > 16645) { throw serverStreamError("TLS wire budget exceeded") }
            pending = serverStreamJoin([pending, bytes])
            let received = ArrayList<Array<Byte>>()
            var offset: Int64 = 0
            while (pending.size-offset >= 5) {
                let kind = pending[offset]
                let minor = pending[offset+2]
                if (pending[offset+1] != 3 || (minor != 3 && !(suite == 0 && kind == 22 && minor == 1))) {
                    throw serverStreamError("invalid TLS record version")
                }
                let length = Int64(pending[offset+3])*256 + Int64(pending[offset+4])
                if (length > 16640 || (kind == 22 && length > 16384)) { throw serverStreamError("TLS record too large") }
                if (pending.size-offset < length+5) { break }
                let wire = pending[offset..offset+5+length].clone()
                offset += 5+length
                if (!ready) { recordCount += 1; if (recordCount > 4096) { throw serverStreamError("TLS handshake budget exceeded") } }
                if (kind == 20) {
                    if (suite == 0 || ready || length != 1 || wire[5] != 1) { throw serverStreamError("unexpected CCS") }
                    continue
                }
                if (suite == 0 && kind == 22) {
                    hello = serverStreamJoin([hello, wire[5..]])
                    if (hello.size > 131072) { throw serverStreamError("ClientHello budget exceeded") }
                    if (hello.size < 4) { continue }
                    let wanted = 4 + Int64(hello[1])*65536 + Int64(hello[2])*256 + Int64(hello[3])
                    if (wanted > 131072 || hello[0] != 1 || hello.size > wanted) { throw serverStreamError("invalid ClientHello flight") }
                    if (hello.size == wanted) { acceptHello() }
                } else if (kind == 23) {
                    let layer = if (ready) { application } else { handshake }
                    let decoded = match (layer) {
                        case Some(value) => value.open(wire)
                        case None => throw serverStreamError("protected TLS record before key exchange")
                    }
                    if (!ready) {
                        if (decoded.contentType != TlsContentType.Handshake) { throw serverStreamError("application data before client Finished") }
                        finished = serverStreamJoin([finished, decoded.fragment])
                        if (finished.size > expectedFinished.size) { throw serverStreamError("unexpected client handshake flight") }
                        if (finished.size == expectedFinished.size) {
                            if (!constantTimeEquals(finished, expectedFinished)) { throw serverStreamError("client Finished verification failed") }
                            ready = true
                            handshake = None
                            expectedFinished = []; finished = []
                        }
                    } else if (decoded.contentType == TlsContentType.ApplicationData) {
                        received.add(decoded.fragment)
                    } else if (decoded.contentType == TlsContentType.Alert) {
                        if (decoded.fragment.size != 2 || decoded.fragment[1] != 0 ||
                            (decoded.fragment[0] != 1 && decoded.fragment[0] != 2) || offset != pending.size) {
                            throw serverStreamError("peer alert or trailing data after close_notify")
                        }
                        let response = match (application) {
                            case Some(value) => value.seal(TlsContentType.Alert, [UInt8(1),UInt8(0)])
                            case None => throw serverStreamError("missing application keys")
                        }
                        let finalBytes = serverStreamJoin([outbound,response])
                        close(); outbound = finalBytes
                        return received.toArray()
                    } else { throw serverStreamError("unsupported post-handshake message") }
                } else { throw serverStreamError("unexpected TLS record") }
            }
            pending = pending[offset..].clone()
            received.toArray()
        } catch (e: CryptoException) {
            close(); throw ContractException(ContractErrorCode.VerifyFailed, "TLS server rejected record: ${e.message}")
        } catch (e: ContractException) { close(); throw e }
    }

    private func acceptHello(): Unit {
        let decoded = tlsDecodeClientHelloHandshake(hello)
        let seen = ArrayList<Int64>()
        var p256Signature = false
        for (ext in decoded.extensions) {
            if (seen.contains(ext.extType)) { throw serverStreamError("duplicate ClientHello extension") }
            seen.add(ext.extType)
            if (ext.extType == 42) { throw serverStreamError("early data is unsupported") }
            if (ext.extType == 13) {
                if (ext.data.size < 4 || ext.data.size % 2 != 0 ||
                    Int64(ext.data[0])*256+Int64(ext.data[1]) != ext.data.size-2) {
                    throw serverStreamError("invalid signature algorithms")
                }
                var i: Int64 = 2
                while (i < ext.data.size) {
                    if (ext.data[i] == 4 && ext.data[i+1] == 3) { p256Signature = true }
                    i += 2
                }
            }
        }
        if (!p256Signature) { throw serverStreamError("client does not offer ECDSA P-256") }
        let ephemeral = x25519GeneratePrivateKey()
        try {
            let key = match (signer) { case Some(value) => value; case None => throw serverStreamError("signer released") }
            let context = tls13BuildServerHandshakeContextX25519(hello, ephemeral,
                x25519PublicFromPrivate(ephemeral), chain, certificatePrivateKeyEcdsa: Some(key), alpnPreference: alpn)
            try {
                let flight = context.flight
                suite = tlsDecodeServerHelloHandshake(flight.serverHello).cipherSuite
                selected = flight.selectedAlpn
                if (requireAlpn && selected.size == 0) { throw serverStreamError("required ALPN was not negotiated") }
                let secrets = context.secrets
                let phase = ContractTls13PhaseSecrets(suite, "handshake", secrets.clientHsTrafficSecret, secrets.serverHsTrafficSecret)
                try { handshake = Some(serverStreamLayer(phase)) } finally { phase.destroy() }
                application = Some(tls13CreateServerRecordLayerHandle(secrets, suite))
                let auth = flight.authFlight
                let transcript = serverStreamJoin([hello, flight.serverHello, flight.encryptedExtensions,
                    auth.certificateHandshake, auth.certificateVerifyHandshake, auth.finishedHandshake])
                let clientSecret = secrets.clientHsTrafficSecret
                try {
                    expectedFinished = tlsEncodeFinishedHandshake(tls13ComputeFinishedVerifyDataForCipherSuite(
                        clientSecret, if (suite == 0x1302) { sha384(transcript) } else { sha256(transcript) }, suite))
                } finally { for (i in 0..clientSecret.size) { clientSecret[i] = 0 } }
                let records = ArrayList<Array<Byte>>()
                records.add(tlsEncodeRecord(TlsContentType.Handshake, TlsVersion.TLS1_2, flight.serverHello))
                let layer = match (handshake) { case Some(value) => value; case None => throw serverStreamError("missing handshake layer") }
                for (message in [flight.encryptedExtensions,auth.certificateHandshake,auth.certificateVerifyHandshake,auth.finishedHandshake]) {
                    var offset: Int64 = 0
                    while (offset < message.size) {
                        let end = if (message.size-offset > 16384) { offset+16384 } else { message.size }
                        records.add(layer.seal(TlsContentType.Handshake, message[offset..end]))
                        offset = end
                    }
                }
                outbound = serverStreamJoin(records.toArray())
                signer = None; hello = []
            } finally { context.secrets.destroy() }
        } finally { for (i in 0..ephemeral.size) { ephemeral[i] = 0 } }
    }

    public func sealApplicationData(bytes: Array<Byte>): Array<Byte> {
        requireOpen()
        if (!ready || outbound.size != 0 || bytes.size > 16384) { throw serverStreamError("drain handshake and establish TLS before writes; maximum 16 KiB") }
        try {
            match (application) { case Some(value) => value.seal(TlsContentType.ApplicationData, bytes)
                case None => throw serverStreamError("missing application layer") }
        } catch (e: CryptoException) { close(); throw serverStreamError(e.message) }
    }
    public func closeNotify(): Array<Byte> {
        requireOpen()
        if (!ready || outbound.size != 0) { throw serverStreamError("drain handshake before close_notify") }
        try {
            match (application) { case Some(value) => value.seal(TlsContentType.Alert, [UInt8(1),UInt8(0)])
                case None => throw serverStreamError("missing application layer") }
        } catch (e: CryptoException) { throw serverStreamError(e.message) } finally { close() }
    }
    public func finishInput(): Unit {
        requireOpen(); close()
        throw serverStreamError("TLS transport EOF without close_notify")
    }
    public func close(): Unit {
        signer = None; handshake = None; application = None
        pending = []; hello = []; finished = []; expectedFinished = []; outbound = []
        ready = false; closed = true
    }
    private func requireOpen(): Unit { if (closed) { throw serverStreamError("TLS server is closed") } }
}

private func serverStreamLayer(secrets: ContractTls13PhaseSecrets): Tls13RecordLayerHandle {
    let (writeKey,writeIv) = secrets.serverTlsKeyIv()
    let (readKey,readIv) = secrets.clientTlsKeyIv()
    try {
        if (secrets.cipherSuite == 0x1303) {
            Tls13RecordLayerHandle(TlsAeadAlgorithm.CHACHA20_POLY1305, chachaLayer: Some(
                TlsChacha20Poly1305RecordLayer(writeKey,writeIv,readKey: readKey,readIv: readIv,version: TlsVersion.TLS1_3)))
        } else {
            Tls13RecordLayerHandle(TlsAeadAlgorithm.AES_GCM, aesLayer: Some(
                TlsAeadRecordLayer(writeKey,writeIv,readKey: readKey,readIv: readIv,version: TlsVersion.TLS1_3)))
        }
    } finally {
        for (i in 0..writeKey.size) { writeKey[i] = 0 }
        for (i in 0..readKey.size) { readKey[i] = 0 }
    }
}
private func serverStreamJoin(parts: Array<Array<Byte>>): Array<Byte> {
    let bytes = ArrayList<Byte>()
    for (part in parts) { for (b in part) { bytes.add(b) } }
    bytes.toArray()
}
private func serverStreamError(message: String): ContractException { ContractException(ContractErrorCode.BadInput,message) }
