package jinguissl.contract

import jinguissl_core.crypto.digest.{sha256, bytesToHexLower}
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.tls.{TlcpIdentity, TlcpProviderPolicy, TlcpProviderException,
    TlcpCipherSuite, tlcpCipherSuiteFromWire, TlcpSession, TlcpRole}

public enum ContractTlcpRole { | Client | Server }

/** Owned, serialized experimental TLCP stream engine. Supply a trusted wall
 * clock for certificate validation and a monotonic clock for start/receive/tick.
 * The caller owns sockets and must drain output in order after every event.
 * A completed server handshake does not imply client certificate authentication:
 * inspect peerAuthenticated, or require client certificates in policy.
 * No native crypto runtime, HTTP parser, ALPN, resumption or downgrade. */
public class ContractTlcpSession {
    private let owned: TlcpSession
    public init(role: ContractTlcpRole, trustAnchorsPem: String, validationTime: String,
        expectedPeerDnsName!: String = "", identity!: ?ContractTlcpIdentity = None,
        policy!: ContractTlcpProviderPolicy = ContractTlcpProviderPolicy()) {
        let coreRole = match (role) { case Client => TlcpRole.Client; case Server => TlcpRole.Server }
        let coreIdentity: ?TlcpIdentity = if (let Some(value) <- identity) { Some(value.owned) } else { None }
        try {
            owned = TlcpSession(coreRole, trustAnchorsPem, validationTime, expectedPeerDnsName: expectedPeerDnsName,
                identity: coreIdentity, policy: policy.owned)
        } catch (e: TlcpProviderException) { throw tlcpRefusal(e) }
          catch (e: CryptoException) { throw ContractException(ContractErrorCode.BadInput, e.message) }
    }
    public prop handshakeComplete: Bool { get() { owned.handshakeComplete } }
    public prop peerAuthenticated: Bool { get() { owned.peerAuthenticated } }
    public prop isClosed: Bool { get() { owned.isClosed } }
    public func start(nowMs: Int64): Unit {
        try { owned.start(nowMs) } catch (e: TlcpProviderException) { throw tlcpRefusal(e) }
        catch (e: CryptoException) { owned.close(); throw ContractException(ContractErrorCode.InternalError, e.message) }
    }
    public func receive(bytes: Array<Byte>, nowMs: Int64): Array<Array<Byte>> {
        try { owned.receive(bytes, nowMs) } catch (e: TlcpProviderException) { throw tlcpRefusal(e) }
        catch (e: CryptoException) { owned.close(); throw ContractException(ContractErrorCode.VerifyFailed, e.message) }
    }
    public func takeOutput(): Array<Array<Byte>> { owned.takeOutput() }
    public func onTimeout(nowMs: Int64): Unit {
        try { owned.onTimeout(nowMs) } catch (e: TlcpProviderException) { throw tlcpRefusal(e) }
    }
    public func sealApplicationData(bytes: Array<Byte>): Array<Byte> {
        try { owned.sealApplicationData(bytes) } catch (e: TlcpProviderException) { throw tlcpRefusal(e) }
    }
    public func peerCertificateHandshake(): Array<Byte> {
        try { owned.peerCertificateHandshake() } catch (e: TlcpProviderException) { throw tlcpRefusal(e) }
    }
    public func selectedCipherSuiteWireValue(): Int64 {
        try { owned.selectedCipherSuite().wireValue() } catch (e: TlcpProviderException) { throw tlcpRefusal(e) }
    }
    public func closeNotify(): Unit {
        try { owned.closeNotify() } catch (e: TlcpProviderException) { throw tlcpRefusal(e) }
        catch (e: CryptoException) { owned.close(); throw ContractException(ContractErrorCode.InternalError, e.message) }
    }
    public func endOfInput(): Unit {
        try { owned.endOfInput() } catch (e: TlcpProviderException) { throw tlcpRefusal(e) }
    }
    public func close(): Unit { owned.close() }
}

private func tlcpRefusal(error: TlcpProviderException): ContractTlcpProviderRefusal {
    ContractTlcpProviderRefusal(error.reason, error.message, alertDescription: error.alertDescription)
}

/** A stable provider refusal, separate from a peer alert received on the wire.
 * The numeric alert is a suggested protocol mapping, not proof of transmission. */
public class ContractTlcpProviderRefusal <: Exception {
    public let reason: String
    public let alertDescription: Int64
    public ContractTlcpProviderRefusal(reason: String, message: String, alertDescription!: Int64 = 80) {
        super(message)
        this.reason = reason; this.alertDescription = alertDescription
    }
}

/** Dual-certificate identity with owned private scalar buffers. Session copies,
 * when supplied by a connection provider, must be closed separately. Caller
 * arrays and managed arithmetic temporaries are not covered by destroy(). */
public class ContractTlcpIdentity {
    internal let owned: TlcpIdentity
    public init(signingPrivateScalar: Array<Byte>, encryptionPrivateScalar: Array<Byte>,
        signingCertificateDer: Array<Byte>, encryptionCertificateDer: Array<Byte>,
        intermediateDer!: Array<Array<Byte>> = []) {
        try {
            this.owned = TlcpIdentity(signingPrivateScalar, encryptionPrivateScalar,
                signingCertificateDer, encryptionCertificateDer, intermediateDer: intermediateDer)
        } catch (e: CryptoException) {
            throw ContractException(ContractErrorCode.BadInput, "TLCP identity: ${e.message}")
        }
    }
    public prop isDestroyed: Bool { get() { owned.isDestroyed } }
    public func certificateHandshake(): Array<Byte> { owned.certificateHandshake() }
    public func destroy(): Unit { owned.destroy() }
}

/** Validated configuration is not evidence of an available connection engine. */
public class ContractTlcpProviderPolicy {
    internal let owned: TlcpProviderPolicy
    public init(cipherSuites!: Array<ContractTlcpCipherSuite> = contractTlcpDefaultCipherSuites(),
        handshakeTimeoutMs!: Int64 = 30000, requireClientCertificate!: Bool = false,
        alpnProtocols!: Array<String> = [], requireHttp2!: Bool = false,
        requestResumption!: Bool = false, requireCertifiedImplementation!: Bool = false) {
        let suites = Array<TlcpCipherSuite>(cipherSuites.size, repeat: TlcpCipherSuite.ECC_SM4_CBC_SM3)
        for (i in 0..cipherSuites.size) { suites[i] = tlcpCipherSuiteFromWire(cipherSuites[i].wireValue()) }
        try {
            this.owned = TlcpProviderPolicy(cipherSuites: suites, handshakeTimeoutMs: handshakeTimeoutMs,
                requireClientCertificate: requireClientCertificate, alpnProtocols: alpnProtocols,
                requireHttp2: requireHttp2, requestResumption: requestResumption,
                requireCertifiedImplementation: requireCertifiedImplementation)
        } catch (e: TlcpProviderException) {
            throw ContractTlcpProviderRefusal(e.reason, e.message, alertDescription: e.alertDescription)
        }
    }
    public prop handshakeTimeoutMs: Int64 { get() { owned.handshakeTimeoutMs } }
    public prop requireClientCertificate: Bool { get() { owned.requireClientCertificate } }
    public func cipherSuites(): Array<ContractTlcpCipherSuite> {
        let suites = owned.cipherSuites()
        let result = Array<ContractTlcpCipherSuite>(suites.size, repeat: ContractTlcpCipherSuite.EccSm4CbcSm3)
        for (i in 0..suites.size) {
            match (suites[i]) {
                case ECDHE_SM4_CBC_SM3 => result[i] = ContractTlcpCipherSuite.EcdheSm4CbcSm3
                case ECC_SM4_CBC_SM3 => result[i] = ContractTlcpCipherSuite.EccSm4CbcSm3
                case ECDHE_SM4_GCM_SM3 => result[i] = ContractTlcpCipherSuite.EcdheSm4GcmSm3
                case ECC_SM4_GCM_SM3 => result[i] = ContractTlcpCipherSuite.EccSm4GcmSm3
            }
        }
        result
    }
}

/** Experimental connection availability, not readiness of any particular
 * session or a certification. See docs/tlcp-provider.md for the fixed peer proof. */
public class ContractTlcpProviderCapabilities {
    public let providerId: String = "jinguissl.tlcp"
    public let contractVersion: Int64 = 1
    public let connectionAvailable: Bool = true
    public let independentInteropVerified: Bool = true
    public let supportsAlpn: Bool = false
    public let supportsHttp2: Bool = false
    public let supportsResumption: Bool = false
    public let refusalReason: String = ""
    public init() {}
    public func requireConnectionReady(): Unit {}
}

public func contractTlcpProviderCapabilities(): ContractTlcpProviderCapabilities {
    ContractTlcpProviderCapabilities()
}

/** Canonical UTF-8 descriptor; no trailing newline. Hash these exact bytes. */
public func contractTlcpProviderDescriptor(): String {
    "jinguissl.tlcp/v1;state=experimental;connection=true;external-interop=true;" +
    "suites=e011,e013,e051,e053;alpn=false;http2=false;resumption=false;certification=false;" +
    "identity=owned-dual-sm2;clock=caller-monotonic-ms;transport=caller-owned"
}

public func contractTlcpProviderDescriptorSha256(): String {
    bytesToHexLower(sha256(contractTlcpProviderDescriptor().toArray()))
}
