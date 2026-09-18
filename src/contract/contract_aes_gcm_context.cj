package jinguissl.contract

import jinguissl_core.crypto.aes.{AesGcmContext, aesGcmEncryptIntoWithContext, aesGcmDecryptIntoWithContext}
import jinguissl_core.crypto.error.CryptoException

/// Caller-serialized reusable key schedule. No Core type or secret getter.
/// Into buffers must be distinct from inputs and from each other.
public class ContractAesGcmContext {
    private var core: ?AesGcmContext = None

    public init(key: Array<Byte>) {
        try { core = Some(AesGcmContext(key)) }
        catch (e: CryptoException) { throw ContractException(ContractErrorCode.BadInput, e.message) }
    }

    public func encryptInto(nonce: Array<Byte>, plaintext: Array<Byte>, ciphertextOut: Array<Byte>,
        tagOut: Array<Byte>, aad!: Array<Byte> = [], tagLen!: Int64 = 16): Unit {
        let ctx = requireContext()
        validate(nonce, plaintext.size, ciphertextOut.size, tagLen)
        if (tagOut.size != tagLen) {
            throw ContractException(ContractErrorCode.BadInput, "AES-GCM tag output length mismatch")
        }
        try { aesGcmEncryptIntoWithContext(ctx, nonce, plaintext, ciphertextOut, tagOut, aad: aad, tagLen: tagLen) }
        catch (e: CryptoException) { throw ContractException(contractMapCoreCryptoException(e), e.message) }
    }

    /// Authentication failure clears plaintextOut; no unauthenticated plaintext is returned.
    public func decryptInto(nonce: Array<Byte>, ciphertext: Array<Byte>, tag: Array<Byte>,
        plaintextOut: Array<Byte>, aad!: Array<Byte> = []): Unit {
        let ctx = requireContext()
        validate(nonce, ciphertext.size, plaintextOut.size, tag.size)
        try { aesGcmDecryptIntoWithContext(ctx, nonce, ciphertext, tag, plaintextOut, aad: aad) }
        catch (_: CryptoException) {
            for (i in 0..plaintextOut.size) { plaintextOut[i] = 0 }
            throw ContractException(ContractErrorCode.VerifyFailed, "AES-GCM authentication failed")
        }
    }

    /// Clears owned mutable schedules and drops context; scalar/GC copies are not guaranteed erased.
    public func destroy(): Unit {
        match (core) {
            case Some(ctx) =>
                for (i in 0..ctx.schedule.key.size) { ctx.schedule.key[i] = 0 }
                for (i in 0..ctx.schedule.roundKeys.size) { ctx.schedule.roundKeys[i] = 0 }
                for (i in 0..ctx.hashSubkey.size) { ctx.hashSubkey[i] = 0 }
                for (i in 0..ctx.ghashTableHi.size) { ctx.ghashTableHi[i] = 0; ctx.ghashTableLo[i] = 0 }
            case None => ()
        }
        core = None
    }

    private func requireContext(): AesGcmContext {
        match (core) {
            case Some(ctx) => ctx
            case None => throw ContractException(ContractErrorCode.BadInput, "AES-GCM context is destroyed")
        }
    }

    private func validate(nonce: Array<Byte>, inputSize: Int64, outputSize: Int64, tagLen: Int64): Unit {
        if (nonce.size == 0 || inputSize != outputSize || tagLen < 4 || tagLen > 16) {
            throw ContractException(ContractErrorCode.BadInput, "AES-GCM nonce, buffer or tag length is invalid")
        }
    }
}
