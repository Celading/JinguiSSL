package jinguissl.contract

import std.collection.ArrayList
import std.sync.Mutex
import jinguissl_core.crypto.base.SecureBytes
import jinguissl_core.crypto.compliance.TlsVersion
import jinguissl_core.crypto.digest.{sha256, sha384}
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.tls.*
import jinguissl_core.crypto.x25519.{x25519GeneratePrivateKey, x25519PublicFromPrivate}
import jinguissl_core.crypto.x509.{X509VerificationPolicy, x509ParsePemChain}

/** One owned copy of a traffic-secret pair. Exports are independent caller-owned
 * snapshots. destroy() is idempotent and best-effort, not a physical-erasure claim.
 * Handshake and application pairs carry distinct phase labels; no master secret
 * or key-exchange private key is exposed by the client engine. */
public class ContractTls13PhaseSecrets {
    public let cipherSuite: Int64
    public let phase: String
    private let mutex = Mutex()
    private let client: SecureBytes
    private let server: SecureBytes

    internal init(cipherSuite: Int64, phase: String, client: Array<Byte>, server: Array<Byte>) {
        this.cipherSuite = cipherSuite
        this.phase = phase
        this.client = SecureBytes(client)
        this.server = SecureBytes(server)
    }

    public prop isDestroyed: Bool { get() { synchronized(mutex) { client.isDestroyed } } }
    public func clientTrafficSecret(): Array<Byte> {
        synchronized(mutex) { requireAlive(); client.bytes() }
    }
    public func serverTrafficSecret(): Array<Byte> {
        synchronized(mutex) { requireAlive(); server.bytes() }
    }
    public func clientTlsKeyIv(): (Array<Byte>, Array<Byte>) {
        synchronized(mutex) {
            requireAlive()
            tls13DeriveApplicationTrafficKeyIv(client.bytes(), keyLen: keyLength())
        }
    }
    public func serverTlsKeyIv(): (Array<Byte>, Array<Byte>) {
        synchronized(mutex) {
            requireAlive()
            tls13DeriveApplicationTrafficKeyIv(server.bytes(), keyLen: keyLength())
        }
    }
    public func destroy(): Unit {
        synchronized(mutex) { client.destroy(); server.destroy() }
    }
    private func keyLength(): Int64 { if (cipherSuite == 0x1301) { 16 } else { 32 } }
    private func requireAlive(): Unit {
        if (client.isDestroyed) { throw engineError("traffic secrets have been destroyed") }
    }
}

/** Application-protocol-independent, certificate-authenticated TLS 1.3 client.
 * Receives ordered, reassembled handshake-stream bytes, NOT TLS records or QUIC
 * packets. The transport must decrypt with the correct encryption level first.
 * Initial accepts only ServerHello; Handshake accepts EE/Certificate/CV/Finished.
 * Supports X25519 and 0x1301/02/03, without HRR, PSK, 0-RTT, client authentication
 * or KeyUpdate. Post-handshake tickets can be validated and discarded, never
 * cached/resumed. No HTTP defaults or unauthenticated application keys.
 */
public class ContractTls13ClientEngine {
    private let mutex = Mutex()
    private let privateKey: SecureBytes
    private let hello: Array<Byte>
    private let policy: X509VerificationPolicy
    private let hostname: String
    private let alpn: Array<String>
    private let requireAlpn: Bool
    private let quic: Bool
    private let suites: Array<Int64>
    private var state: Int64 = 0
    private var suite: Int64 = 0
    private var pending: Array<Byte> = []
    private var received: Int64 = 0
    private let messages = ArrayList<Array<Byte>>()
    private var handshake: ?ContractTls13PhaseSecrets = None
    private var application: ?ContractTls13PhaseSecrets = None
    private var selected: String = ""
    private var peerParameters: Array<Byte> = []
    private var peerChain: Array<Array<Byte>> = []
    private var finished: Array<Byte> = []
    private var postBytes: Int64 = 0
    private var failureAlert: ?Int64 = None

    public init(
        trustAnchorsPem: String,
        hostname: String,
        validationTime: String,
        alpnProtocols!: Array<String> = [],
        requireAlpn!: Bool = false,
        cipherSuites!: Array<Int64> = [0x1301, 0x1302, 0x1303],
        quicTransportParameters!: ?Array<Byte> = None
    ) {
        if (hostname.size == 0 || hostname != hostname.trimAscii() || validationTime.size == 0) {
            throw engineError("explicit DNS hostname and certificate validation time are required")
        }
        if (cipherSuites.size == 0) { throw engineError("at least one cipher suite is required") }
        for (value in cipherSuites) {
            if (value != 0x1301 && value != 0x1302 && value != 0x1303) {
                throw engineError("client engine supports only TLS 1.3 suites 0x1301/02/03")
            }
        }
        let isQuic = quicTransportParameters.isSome()
        if ((requireAlpn || isQuic) && alpnProtocols.size == 0) {
            throw engineError("this client requires an explicit ALPN offer")
        }
        for (value in alpnProtocols) {
            if (value.size == 0 || value != value.trimAscii()) {
                throw engineError("ALPN tokens must be nonempty and must not need normalization")
            }
        }
        try {
            this.policy = X509VerificationPolicy(
                x509ParsePemChain(trustAnchorsPem),
                requiredLeafDnsName: hostname,
                validationTime: validationTime,
                requiredLeafKeyUsageMask: 1,
                requiredLeafExtendedKeyUsages: ["1.3.6.1.5.5.7.3.1"]
            )
            let (ownedKey, encodedHello) = buildEngineHello(cipherSuites, hostname, alpnProtocols, quicTransportParameters)
            this.privateKey = ownedKey
            this.hello = encodedHello
        } catch (e: CryptoException) {
            throw ContractException(ContractErrorCode.BadInput, "TLS client initialization: ${e.message}")
        }
        this.hostname = hostname
        this.alpn = alpnProtocols.clone()
        this.requireAlpn = requireAlpn || isQuic
        this.quic = isQuic
        this.suites = cipherSuites.clone()
    }

    public func clientHello(): Array<Byte> { synchronized(mutex) { requireOpen(); hello.clone() } }
    public prop authenticated: Bool { get() { synchronized(mutex) { state == 5 } } }
    public prop isClosed: Bool { get() { synchronized(mutex) { state < 0 } } }
    /** Exact extension/ALPN alert when known; transport owns wire error emission. */
    public prop failureAlertDescription: ?Int64 { get() { synchronized(mutex) { failureAlert } } }
    public prop cipherSuite: Int64 { get() { synchronized(mutex) { requireOpen(); suite } } }
    public func receiveInitial(bytes: Array<Byte>): Unit { receive(bytes, true) }
    public func receiveHandshake(bytes: Array<Byte>): Unit { receive(bytes, false) }
    public func handshakeSecrets(): ContractTls13PhaseSecrets {
        synchronized(mutex) {
            requireOpen()
            match (handshake) {
                case Some(value) => copyPhase(value)
                case None => throw engineError("handshake keys require a validated ServerHello")
            }
        }
    }
    public func applicationSecrets(): ContractTls13PhaseSecrets {
        synchronized(mutex) {
            requireAuthenticated()
            match (application) {
                case Some(value) => copyPhase(value)
                case None => throw engineError("application secrets are unavailable")
            }
        }
    }
    public func selectedAlpn(): String { synchronized(mutex) { requireAuthenticated(); selected } }
    public func peerTransportParameters(): Array<Byte> {
        synchronized(mutex) { requireAuthenticated(); peerParameters.clone() }
    }
    public func peerCertificateChainDer(): Array<Array<Byte>> {
        synchronized(mutex) { requireAuthenticated(); cloneChain(peerChain) }
    }
    public func clientFinished(): Array<Byte> { synchronized(mutex) { requireAuthenticated(); finished.clone() } }
    public func close(): Unit { synchronized(mutex) { closeOwned() } }

    /** Feed authenticated Application/One-RTT-level handshake bytes. Only validates
     * and discards NewSessionTicket; no PSK, 0-RTT or resumption state is created. */
    public func receivePostHandshake(bytes: Array<Byte>): Unit {
        synchronized(mutex) {
            requireAuthenticated()
            try {
                if (bytes.size > 262144 - postBytes) { throw engineError("post-handshake ticket budget exceeded") }
                postBytes += bytes.size
                pending = joinEngineBytes([pending, bytes])
                while (pending.size >= 4) {
                    if (pending[0] != 4) { throw engineError("only discarded NewSessionTicket is supported after handshake") }
                    let length = (Int64(pending[1]) << 16) | (Int64(pending[2]) << 8) | Int64(pending[3])
                    if (length > 262140) { throw engineError("post-handshake message exceeds budget") }
                    if (pending.size < length + 4) { break }
                    _ = tls13DecodeNewSessionTicketHandshake(pending[..(length + 4)])
                    pending = pending[(length + 4)..].clone()
                }
            } catch (e: CryptoException) {
                closeOwned()
                throw ContractException(ContractErrorCode.BadInput, "post-handshake ticket rejected: ${e.message}")
            } catch (e: ContractException) {
                closeOwned()
                throw e
            }
        }
    }

    private func receive(bytes: Array<Byte>, initial: Bool): Unit {
        synchronized(mutex) {
            requireOpen()
            try {
                if (state == 5 || (initial && state != 0) || (!initial && state == 0)) {
                    throw engineError("wrong handshake encryption level or terminal message")
                }
                if (bytes.size > 262144 - received) { throw engineError("handshake exceeds 256 KiB budget") }
                received += bytes.size
                pending = joinEngineBytes([pending, bytes])
                while (pending.size >= 4) {
                    let expected: Array<Byte> = [2, 8, 11, 15, 20]
                    if (state >= 5 || pending[0] != expected[state]) {
                        throw engineError("unexpected TLS handshake message order")
                    }
                    let length = (Int64(pending[1]) << 16) | (Int64(pending[2]) << 8) | Int64(pending[3])
                    if (length > 262140) { throw engineError("handshake message exceeds bounded budget") }
                    if (pending.size < length + 4) { break }
                    let message = pending[..(length + 4)].clone()
                    pending = pending[(length + 4)..].clone()
                    if (state == 0) {
                        if (pending.size != 0) { throw engineError("ServerHello must end the Initial encryption level") }
                        acceptServerHello(message)
                    } else if (state == 1) {
                        acceptExtensions(message)
                    } else if (state == 2) {
                        let cert = tlsDecodeCertificateHandshakeTls13(message)
                        if (cert.requestContext.size != 0) { throw engineError("server certificate context must be empty") }
                        for (entry in cert.entries) {
                            if (entry.extensions.size != 0) { throw engineError("unsolicited certificate extensions") }
                        }
                    } else if (state == 3) {
                        if (message.size < 8) { throw engineError("truncated CertificateVerify") }
                        let scheme = (Int64(message[4]) << 8) | Int64(message[5])
                        if (scheme != 0x0403 && scheme != 0x0503 && scheme != 0x0804) {
                            throw engineError("CertificateVerify selected an unoffered signature scheme")
                        }
                    }
                    messages.add(message)
                    if (state == 4) { authenticateFlight() }
                    state += 1
                    if (state == 5 && pending.size != 0) { throw engineError("post-handshake data is not accepted by this engine") }
                }
            } catch (e: CryptoException) {
                closeOwned()
                throw ContractException(ContractErrorCode.VerifyFailed, "TLS handshake rejected: ${e.message}")
            } catch (e: ContractException) {
                closeOwned()
                throw e
            }
        }
    }

    private func acceptServerHello(message: Array<Byte>): Unit {
        let sh = tlsDecodeServerHelloHandshake(message)
        let retryRandom = sha256("HelloRetryRequest".toArray())
        var isRetry = true
        for (i in 0..32) { if (sh.random[i] != retryRandom[i]) { isRetry = false } }
        if (isRetry) { throw engineError("HelloRetryRequest is not supported by this client") }
        if (sh.legacyVersion != TlsVersion.TLS1_2 || sh.compressionMethod != 0 || sh.sessionId.size != 0) {
            throw engineError("invalid ServerHello legacy fields")
        }
        var offered = false
        for (value in suites) { if (value == sh.cipherSuite) { offered = true } }
        if (!offered) { throw engineError("server selected an unoffered cipher suite") }
        let seen = ArrayList<Int64>()
        for (ext in sh.extensions) {
            for (value in seen) { if (value == ext.extType) { throw engineError("duplicate ServerHello extension") } }
            seen.add(ext.extType)
            if (ext.extType != 43 && ext.extType != 51) { throw engineError("unsupported ServerHello extension") }
            if (ext.extType == 43 && (ext.data.size != 2 || ext.data[0] != 3 || ext.data[1] != 4)) {
                throw engineError("server did not negotiate TLS 1.3")
            }
        }
        if (seen.size != 2) { throw engineError("ServerHello requires supported_versions and key_share") }
        suite = sh.cipherSuite
        let secrets = tls13DeriveSecretsFromX25519ForCipherSuite(
            privateKey.bytes(), tls13ExtractServerX25519KeyShare(message), digest(joinEngineBytes([hello, message])), suite
        )
        handshake = Some(ContractTls13PhaseSecrets(suite, "handshake", secrets.clientHsTrafficSecret, secrets.serverHsTrafficSecret))
        secrets.destroy()
    }

    private func acceptExtensions(message: Array<Byte>): Unit {
        let ee = tlsDecodeEncryptedExtensionsHandshake(message)
        let seen = ArrayList<Int64>()
        var hasParameters = false
        for (ext in ee.extensions) {
            for (value in seen) { if (value == ext.extType) { throw engineError("duplicate EncryptedExtensions extension") } }
            seen.add(ext.extType)
            if (ext.extType == 16) {
                let protocols = tlsParseAlpnExtension(ext)
                if (protocols.size != 1) { throw engineError("server must select exactly one ALPN token") }
                var offered = false
                for (value in alpn) { if (value == protocols[0]) { offered = true } }
                if (!offered) { failureAlert = Some(120); throw engineError("server selected an unoffered ALPN token") }
                selected = protocols[0]
            } else if (ext.extType == 0) {
                if (ext.data.size != 0) { throw engineError("server_name acknowledgement must be empty") }
            } else if (ext.extType == 0x39 && quic) {
                peerParameters = ext.data.clone()
                hasParameters = true
            } else {
                failureAlert = Some(110)
                throw engineError("unsupported or unsolicited EncryptedExtensions extension")
            }
        }
        if (requireAlpn && selected.size == 0) { failureAlert = Some(120); throw engineError("required ALPN was not selected") }
        if (quic && !hasParameters) { failureAlert = Some(109); throw engineError("QUIC peer transport parameters are required") }
    }

    private func authenticateFlight(): Unit {
        let flight = Tls13ServerHandshakeFlight(
            messages[0], messages[1],
            Tls13AuthFlight(Tls13AuthFlightRole.SERVER, messages[2], messages[3], messages[4]),
            digest(joinEngineBytes([hello, messages[0], messages[1]])), requestedServerName: hostname
        )
        let result = tls13ProcessServerHandshakeFlightX25519(hello, privateKey.bytes(), flight, policy)
        try {
            application = Some(ContractTls13PhaseSecrets(
                suite, "application", result.secrets.clientAppTrafficSecret, result.secrets.serverAppTrafficSecret
            ))
            finished = tlsEncodeFinishedHandshake(tls13ComputeFinishedVerifyDataForCipherSuite(
                result.secrets.clientHsTrafficSecret,
                digest(joinEngineBytes([hello, messages[0], messages[1], messages[2], messages[3], messages[4]])), suite
            ))
            let chain = ArrayList<Array<Byte>>()
            for (cert in result.verification.chain) { chain.add(cert.der.clone()) }
            peerChain = chain.toArray()
        } finally {
            result.secrets.destroy()
            privateKey.destroy()
        }
    }
    private func digest(bytes: Array<Byte>): Array<Byte> {
        if (suite == 0x1302) { sha384(bytes) } else { sha256(bytes) }
    }
    private func requireOpen(): Unit { if (state < 0) { throw engineError("TLS client engine is closed") } }
    private func requireAuthenticated(): Unit {
        if (state != 5) { throw engineError("server authentication has not completed") }
    }
    private func closeOwned(): Unit {
        privateKey.destroy()
        if (let Some(value) <- handshake) { value.destroy() }
        if (let Some(value) <- application) { value.destroy() }
        handshake = None
        application = None
        pending = []
        messages.clear()
        finished = []
        peerChain = []
        peerParameters = []
        state = -1
    }
}

private func engineError(message: String): ContractException { ContractException(ContractErrorCode.BadInput, message) }
private func joinEngineBytes(parts: Array<Array<Byte>>): Array<Byte> {
    let out = ArrayList<Byte>()
    for (part in parts) { for (byte in part) { out.add(byte) } }
    out.toArray()
}
private func cloneChain(chain: Array<Array<Byte>>): Array<Array<Byte>> {
    let out = ArrayList<Array<Byte>>()
    for (cert in chain) { out.add(cert.clone()) }
    out.toArray()
}
private func copyPhase(value: ContractTls13PhaseSecrets): ContractTls13PhaseSecrets {
    let client = value.clientTrafficSecret()
    let server = value.serverTrafficSecret()
    try { ContractTls13PhaseSecrets(value.cipherSuite, value.phase, client, server) } finally {
        for (i in 0..client.size) { client[i] = 0 }
        for (i in 0..server.size) { server[i] = 0 }
    }
}

private func buildEngineHello(
    suites: Array<Int64>, hostname: String, alpn: Array<String>, parameters: ?Array<Byte>
): (SecureBytes, Array<Byte>) {
    let key = x25519GeneratePrivateKey()
    try {
        let base = tlsDecodeClientHelloHandshake(tls13BuildClientHelloX25519WithCipherSuites(
            x25519PublicFromPrivate(key), suites
        ))
        let extensions = ArrayList<TlsExtension>()
        for (ext in base.extensions) { extensions.add(ext) }
        extensions.add(tlsBuildServerNameExtension(hostname))
        if (alpn.size > 0) { extensions.add(tlsBuildAlpnExtension(alpn)) }
        if (let Some(bytes) <- parameters) {
            if (bytes.size > 65535) { throw engineError("QUIC transport parameters exceed extension limit") }
            extensions.add(TlsExtension(0x39, bytes))
        }
        let encoded = tlsEncodeClientHelloHandshake(TlsClientHello(
            base.random, base.cipherSuites, sessionId: base.sessionId, extensions: extensions.toArray()
        ))
        (SecureBytes(key), encoded)
    } finally {
        for (i in 0..key.size) { key[i] = 0 }
    }
}
