package jinguissl.contract

import jinguissl_core.crypto.digest.{Blake2sContext, blake2s}
import jinguissl_core.crypto.chacha20.{hchacha20, xchacha20Poly1305Encrypt, xchacha20Poly1305Decrypt}
import jinguissl_core.crypto.error.CryptoException

/// Sequential BLAKE2s, including native variable digest length and keyed mode.
public class ContractBlake2sContext {
    private let core: Blake2sContext
    public init(key!: Array<Byte> = [], digestLength!: Int64 = 32) {
        try { this.core = Blake2sContext(key: key, digestLength: digestLength) }
        catch (e: CryptoException) { throw contractExtendedCryptoError(e) }
    }
    public func update(input: Array<Byte>): Unit {
        try { core.update(input) } catch (e: CryptoException) { throw contractExtendedCryptoError(e) }
    }
    public func finalDigest(): Array<Byte> {
        try { core.finalDigest() } catch (e: CryptoException) { throw contractExtendedCryptoError(e) }
    }
    public func destroy(): Unit { core.destroy() }
}

public func contractBlake2s(input: Array<Byte>, key!: Array<Byte> = [], digestLength!: Int64 = 32): Array<Byte> {
    try { blake2s(input, key: key, digestLength: digestLength) }
    catch (e: CryptoException) { throw contractExtendedCryptoError(e) }
}

public func contractHchacha20(key: Array<Byte>, nonce: Array<Byte>): Array<Byte> {
    try { hchacha20(key, nonce) } catch (e: CryptoException) { throw contractExtendedCryptoError(e) }
}

public func contractXchacha20Poly1305Encrypt(key: Array<Byte>, nonce: Array<Byte>,
    plaintext: Array<Byte>, aad!: Array<Byte> = []): (Array<Byte>, Array<Byte>) {
    try { xchacha20Poly1305Encrypt(key, nonce, plaintext, aad: aad) }
    catch (e: CryptoException) { throw contractExtendedCryptoError(e) }
}

public func contractXchacha20Poly1305Decrypt(key: Array<Byte>, nonce: Array<Byte>,
    ciphertext: Array<Byte>, tag: Array<Byte>, aad!: Array<Byte> = []): Array<Byte> {
    if (key.size != 32 || nonce.size != 24 || tag.size != 16) {
        throw ContractException(ContractErrorCode.BadInput, "XChaCha20-Poly1305 key/nonce/tag length is invalid")
    }
    try { xchacha20Poly1305Decrypt(key, nonce, ciphertext, tag, aad: aad) }
    catch (_: CryptoException) {
        throw ContractException(ContractErrorCode.VerifyFailed, "XChaCha20-Poly1305 authentication failed")
    }
}

private func contractExtendedCryptoError(e: CryptoException): ContractException {
    ContractException(contractMapCoreCryptoException(e), e.message)
}
