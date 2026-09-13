package jinguissl.contract

import std.sync.Mutex
import jinguissl_core.crypto.base.SecureBytes
import jinguissl_core.crypto.dtls.{DtlsIdentity, DtlsAssociation, DtlsRole}
import jinguissl_core.crypto.error.CryptoException

public enum ContractDtlsRole { | Client | Server }

/** P-256 signing identity for fingerprint-authenticated DTLS. The certificate
 * and its SHA-256 fingerprint are public snapshots; private scalars stay owned.
 * Sessions clone the identity, so destroying this object does not revoke an
 * already-created session. Close each session separately. */
public class ContractDtlsIdentity {
    internal let owned: DtlsIdentity
    public init(privateKeyPkcs8Pem: String, certificateDer: Array<Byte>) {
        try { this.owned = DtlsIdentity(privateKeyPkcs8Pem, certificateDer) }
        catch (e: CryptoException) { throw dtlsInput(e.message) }
    }
    private init(identity: DtlsIdentity) { this.owned = identity }
    public static func generate(commonName: String, notBefore: String, notAfter: String): ContractDtlsIdentity {
        try { ContractDtlsIdentity(DtlsIdentity.generate(commonName, notBefore, notAfter)) }
        catch (e: CryptoException) { throw dtlsInput(e.message) }
    }
    public func certificateDer(): Array<Byte> { owned.certificateDer() }
    public func fingerprintSha256(): String { owned.fingerprintSha256() }
    public func destroy(): Unit { owned.destroy() }
}

/** Caller-owned RFC 5764 exporter snapshot, in protocol client/server direction
 * (not local/remote direction). Each getter clones. destroy() revokes this
 * snapshot only and wipes its owned buffers best-effort, not all caller copies. */
public class ContractDtlsSrtpSecrets {
    public let profile: Int64
    private let mutex = Mutex()
    private let clientKey: SecureBytes
    private let serverKey: SecureBytes
    private let clientSalt: SecureBytes
    private let serverSalt: SecureBytes
    internal init(profile: Int64, ck: Array<Byte>, sk: Array<Byte>, cs: Array<Byte>, ss: Array<Byte>) {
        this.profile = profile
        clientKey = SecureBytes(ck); serverKey = SecureBytes(sk)
        clientSalt = SecureBytes(cs); serverSalt = SecureBytes(ss)
    }
    public prop isDestroyed: Bool { get() { synchronized(mutex) { clientKey.isDestroyed } } }
    private func requireAlive(): Unit {
        if (clientKey.isDestroyed) { throw dtlsInput("SRTP secrets have been destroyed") }
    }
    public func clientWriteKey(): Array<Byte> { synchronized(mutex) { requireAlive(); clientKey.bytes() } }
    public func serverWriteKey(): Array<Byte> { synchronized(mutex) { requireAlive(); serverKey.bytes() } }
    public func clientWriteSalt(): Array<Byte> { synchronized(mutex) { requireAlive(); clientSalt.bytes() } }
    public func serverWriteSalt(): Array<Byte> { synchronized(mutex) { requireAlive(); serverSalt.bytes() } }
    public func destroy(): Unit {
        synchronized(mutex) { clientKey.destroy(); serverKey.destroy(); clientSalt.destroy(); serverSalt.destroy() }
    }
}

/** Transport-independent DTLS 1.2, X25519/ECDSA-P256/AES128-GCM-SHA256 with
 * mandatory EMS. SRTP profiles 7 (AEAD AES128 GCM) and 1 (AES128 CM SHA1 80).
 * Server requires client certificate proof. Fingerprints must be obtained via
 * trusted signaling; this is NOT PKIX/hostname validation. No ICE, RTP, SCTP,
 * SDP parsing, resumption, renegotiation, PSK, DTLS 1.3 or socket ownership.
 * Serialize UDP receive/time events, use a monotonic millisecond clock, and
 * drain output after every event before sending application data. */
public class ContractDtlsSession {
    private let owned: DtlsAssociation
    public init(role: ContractDtlsRole, identity: ContractDtlsIdentity, expectedPeerSha256: String,
        peerEndpointBinding: Array<Byte>, srtpProfiles!: Array<Int64> = [7, 1]) {
        let profiles = Array<UInt16>(srtpProfiles.size, repeat: 0)
        for (i in 0..profiles.size) {
            if (srtpProfiles[i] != 1 && srtpProfiles[i] != 7) {
                throw dtlsInput("supported SRTP profiles are 7 and 1")
            }
            profiles[i] = UInt16(srtpProfiles[i])
        }
        let coreRole = match (role) { case Client => DtlsRole.Client; case Server => DtlsRole.Server }
        try { this.owned = DtlsAssociation(coreRole, identity.owned, expectedPeerSha256,
            peerEndpointBinding, profiles: profiles) }
        catch (e: CryptoException) { throw dtlsInput(e.message) }
    }
    public prop authenticated: Bool { get() { owned.authenticated } }
    public prop isClosed: Bool { get() { owned.isClosed } }
    public func start(nowMs: Int64): Unit {
        try { owned.start(nowMs) } catch (e: CryptoException) { throw dtlsInput(e.message) }
    }
    public func receive(datagram: Array<Byte>, nowMs: Int64): Array<Array<Byte>> {
        try { owned.receive(datagram, nowMs) }
        catch (e: CryptoException) { throw ContractException(ContractErrorCode.VerifyFailed, "DTLS receive: ${e.message}") }
    }
    public func takeOutput(): Array<Array<Byte>> { owned.takeOutput() }
    public func onTimeout(nowMs: Int64): Unit {
        try { owned.onTimeout(nowMs) } catch (e: CryptoException) { throw dtlsInput(e.message) }
    }
    public func sealApplicationData(bytes: Array<Byte>): Array<Byte> {
        try { owned.sealApplicationData(bytes) } catch (e: CryptoException) { throw dtlsInput(e.message) }
    }
    public func selectedSrtpProfile(): Int64 {
        try { Int64(owned.selectedSrtpProfile()) } catch (e: CryptoException) { throw dtlsInput(e.message) }
    }
    public func peerCertificateDer(): Array<Byte> {
        try { owned.peerCertificateDer() } catch (e: CryptoException) { throw dtlsInput(e.message) }
    }
    public func exportSrtp(): ContractDtlsSrtpSecrets {
        try {
            let keys = owned.exportSrtp()
            try {
                ContractDtlsSrtpSecrets(Int64(keys.profile.toCode()), keys.clientWriteKey, keys.serverWriteKey,
                    keys.clientWriteSalt, keys.serverWriteSalt)
            } finally {
                for (bytes in [keys.clientWriteKey, keys.serverWriteKey, keys.clientWriteSalt, keys.serverWriteSalt]) {
                    for (i in 0..bytes.size) { bytes[i] = 0 }
                }
            }
        } catch (e: CryptoException) { throw dtlsInput(e.message) }
    }
    public func closeNotify(): Unit {
        try { owned.closeNotify() } catch (e: CryptoException) { throw dtlsInput(e.message) }
    }
    public func close(): Unit { owned.close() }
}

private func dtlsInput(message: String): ContractException {
    ContractException(ContractErrorCode.BadInput, "DTLS: ${message}")
}
