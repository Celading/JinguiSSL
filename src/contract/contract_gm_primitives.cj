package jinguissl.contract

import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.drbg.{Sm3HashDrbg, Sm4CtrDrbg, sm3HashDrbgFromSystem, sm4CtrDrbgFromSystem}
import jinguissl_core.crypto.error.{CryptoErrorCode, CryptoException}
import jinguissl_core.crypto.sm2.*
import jinguissl_core.crypto.sm3.{sm3, hmacSm3, sm3Kdf}
import jinguissl_core.crypto.sm4.*

public let CONTRACT_SM2_PRIVATE_KEY_LEN: Int64 = 32
public let CONTRACT_SM2_PUBLIC_KEY_LEN: Int64 = 65
public let CONTRACT_SM2_SIGNATURE_LEN: Int64 = 64
public let CONTRACT_SM3_DIGEST_LEN: Int64 = 32
public let CONTRACT_SM4_KEY_LEN: Int64 = 16
public let CONTRACT_SM4_BLOCK_LEN: Int64 = 16

/** Stable byte-only SM2 key material. The private scalar is intentionally explicit. */
public class ContractSm2KeyPair {
    public let privateKey: Array<Byte>
    public let publicKey: Array<Byte>

    public init(privateKey: Array<Byte>, publicKey: Array<Byte>) {
        contractGmRequireSize(privateKey, CONTRACT_SM2_PRIVATE_KEY_LEN, "SM2 private key")
        contractGmRequireSize(publicKey, CONTRACT_SM2_PUBLIC_KEY_LEN, "SM2 public key")
        this.privateKey = privateKey.clone()
        this.publicKey = publicKey.clone()
    }
}

/** Raw SM2 signature encoded as the fixed-width pair r || s. */
public class ContractSm2Signature {
    public let encoded: Array<Byte>

    public init(encoded: Array<Byte>) {
        contractGmRequireSize(encoded, CONTRACT_SM2_SIGNATURE_LEN, "SM2 signature")
        this.encoded = encoded.clone()
    }

    public func r(): Array<Byte> { encoded[..32] }
    public func s(): Array<Byte> { encoded[32..] }
}

public class ContractSm2KeyExchangeResult {
    public let key: Array<Byte>
    public let sendConfirmation: Array<Byte>
    public let expectedPeerConfirmation: Array<Byte>

    public init(
        key: Array<Byte>,
        sendConfirmation: Array<Byte>,
        expectedPeerConfirmation: Array<Byte>
    ) {
        if (key.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "SM2 shared key must not be empty")
        }
        contractGmRequireSize(sendConfirmation, 32, "SM2 send confirmation")
        contractGmRequireSize(expectedPeerConfirmation, 32, "SM2 peer confirmation")
        this.key = key.clone()
        this.sendConfirmation = sendConfirmation.clone()
        this.expectedPeerConfirmation = expectedPeerConfirmation.clone()
    }
}

public enum ContractSm4Mode <: Equatable<ContractSm4Mode> & ToString {
    | Ecb
    | Cbc
    | Ctr
    | Cfb
    | Ofb
    | Xts
    | Hctr

    public operator func ==(right: ContractSm4Mode): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case Ecb => 0
            case Cbc => 1
            case Ctr => 2
            case Cfb => 3
            case Ofb => 4
            case Xts => 5
            case Hctr => 6
        }
    }

    public func toString(): String {
        match (this) {
            case Ecb => "SM4-ECB"
            case Cbc => "SM4-CBC"
            case Ctr => "SM4-CTR"
            case Cfb => "SM4-CFB128"
            case Ofb => "SM4-OFB"
            case Xts => "SM4-XTS"
            case Hctr => "SM4-HCTR"
        }
    }
}

public enum ContractSm4AeadAlgorithm <: Equatable<ContractSm4AeadAlgorithm> & ToString {
    | Gcm
    | Ccm

    public operator func ==(right: ContractSm4AeadAlgorithm): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case Gcm => 0
            case Ccm => 1
        }
    }

    public func toString(): String {
        match (this) {
            case Gcm => "SM4-GCM"
            case Ccm => "SM4-CCM"
        }
    }
}

public class ContractSm4AeadResult {
    public let ciphertext: Array<Byte>
    public let tag: Array<Byte>

    public init(ciphertext: Array<Byte>, tag: Array<Byte>) {
        if (tag.size < 4 || tag.size > 16) {
            throw ContractException(ContractErrorCode.BadInput, "SM4 AEAD tag must be 4..16 bytes")
        }
        this.ciphertext = ciphertext.clone()
        this.tag = tag.clone()
    }
}

public func contractSm3(data: Array<Byte>): Array<Byte> { sm3(data) }

public func contractHmacSm3(key: Array<Byte>, data: Array<Byte>): Array<Byte> {
    hmacSm3(key, data)
}

public func contractSm3Kdf(input: Array<Byte>, outputLen: Int64): Array<Byte> {
    try {
        sm3Kdf(input, outputLen)
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, "SM3 KDF")
    }
}

public func contractSm4Encrypt(
    mode: ContractSm4Mode,
    key: Array<Byte>,
    input: Array<Byte>,
    parameter!: Array<Byte> = [],
    pkcs7!: Bool = false
): Array<Byte> {
    try {
        match (mode) {
            case Ecb => sm4EcbEncrypt(key, input, pkcs7: pkcs7)
            case Cbc => sm4CbcEncrypt(key, parameter, input, pkcs7: pkcs7)
            case Ctr => sm4CtrCrypt(key, parameter, input)
            case Cfb => sm4CfbEncrypt(key, parameter, input)
            case Ofb => sm4OfbCrypt(key, parameter, input)
            case Xts => sm4XtsEncrypt(key, parameter, input)
            case Hctr => sm4HctrEncrypt(key, parameter, input)
        }
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, mode.toString() + " encryption")
    }
}

public func contractSm4Decrypt(
    mode: ContractSm4Mode,
    key: Array<Byte>,
    input: Array<Byte>,
    parameter!: Array<Byte> = [],
    pkcs7!: Bool = false
): Array<Byte> {
    try {
        match (mode) {
            case Ecb => sm4EcbDecrypt(key, input, pkcs7: pkcs7)
            case Cbc => sm4CbcDecrypt(key, parameter, input, pkcs7: pkcs7)
            case Ctr => sm4CtrCrypt(key, parameter, input)
            case Cfb => sm4CfbDecrypt(key, parameter, input)
            case Ofb => sm4OfbCrypt(key, parameter, input)
            case Xts => sm4XtsDecrypt(key, parameter, input)
            case Hctr => sm4HctrDecrypt(key, parameter, input)
        }
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, mode.toString() + " decryption")
    }
}

public func contractSm4AeadEncrypt(
    algorithm: ContractSm4AeadAlgorithm,
    key: Array<Byte>,
    nonce: Array<Byte>,
    plaintext: Array<Byte>,
    aad!: Array<Byte> = [],
    tagLen!: Int64 = 16
): ContractSm4AeadResult {
    try {
        let (ciphertext, tag) = match (algorithm) {
            case Gcm => sm4GcmEncrypt(key, nonce, plaintext, aad: aad, tagLen: tagLen)
            case Ccm => sm4CcmEncrypt(key, nonce, plaintext, aad: aad, tagLen: tagLen)
        }
        ContractSm4AeadResult(ciphertext, tag)
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, algorithm.toString() + " encryption")
    }
}

public func contractSm4AeadDecrypt(
    algorithm: ContractSm4AeadAlgorithm,
    key: Array<Byte>,
    nonce: Array<Byte>,
    ciphertext: Array<Byte>,
    tag: Array<Byte>,
    aad!: Array<Byte> = []
): Array<Byte> {
    try {
        match (algorithm) {
            case Gcm => sm4GcmDecrypt(key, nonce, ciphertext, tag, aad: aad)
            case Ccm => sm4CcmDecrypt(key, nonce, ciphertext, tag, aad: aad)
        }
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, algorithm.toString() + " decryption")
    }
}

public func contractSm4Cmac(
    key: Array<Byte>, message: Array<Byte>, tagLen!: Int64 = 16
): Array<Byte> {
    try {
        sm4Cmac(key, message, tagLen: tagLen)
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, "SM4-CMAC")
    }
}

public func contractSm4CbcMac(
    key: Array<Byte>, message: Array<Byte>, tagLen!: Int64 = 16
): Array<Byte> {
    try {
        sm4CbcMac(key, message, tagLen: tagLen)
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, "SM4-CBC-MAC")
    }
}

public func contractSm2GenerateKeyPair(): ContractSm2KeyPair {
    try {
        let privateKey = sm2GeneratePrivateKey()
        ContractSm2KeyPair(
            privateKey.scalar.toBytesBE(paddedLen: CONTRACT_SM2_PRIVATE_KEY_LEN),
            sm2PublicKeyToUncompressed(sm2PublicKey(privateKey))
        )
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, "SM2 key generation")
    }
}

public func contractSm2PublicFromPrivate(privateKey: Array<Byte>): Array<Byte> {
    try {
        sm2PublicKeyToUncompressed(sm2PublicKey(contractGmSm2PrivateKey(privateKey)))
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, "SM2 public-key derivation")
    }
}

public func contractSm2ComputeZa(identity: Array<Byte>, publicKey: Array<Byte>): Array<Byte> {
    try {
        sm2ComputeZa(identity, sm2PublicKeyFromUncompressed(publicKey))
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, "SM2 ZA computation")
    }
}

public func contractSm2Sign(
    privateKey: Array<Byte>, identity: Array<Byte>, message: Array<Byte>
): ContractSm2Signature {
    try {
        let (r, s) = sm2Sign(contractGmSm2PrivateKey(privateKey), identity, message)
        ContractSm2Signature(contractGmConcat([
            r.toBytesBE(paddedLen: 32), s.toBytesBE(paddedLen: 32)
        ]))
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, "SM2 signing")
    }
}

public func contractSm2Verify(
    publicKey: Array<Byte>,
    identity: Array<Byte>,
    message: Array<Byte>,
    signature: ContractSm2Signature
): Bool {
    try {
        sm2Verify(
            sm2PublicKeyFromUncompressed(publicKey), identity, message,
            BigNum.fromBytesBE(signature.r()), BigNum.fromBytesBE(signature.s())
        )
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, "SM2 verification")
    }
}

public func contractSm2Encrypt(publicKey: Array<Byte>, plaintext: Array<Byte>): Array<Byte> {
    try {
        sm2Encrypt(sm2PublicKeyFromUncompressed(publicKey), plaintext)
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, "SM2 encryption")
    }
}

public func contractSm2Decrypt(privateKey: Array<Byte>, ciphertext: Array<Byte>): Array<Byte> {
    try {
        sm2Decrypt(contractGmSm2PrivateKey(privateKey), ciphertext)
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, "SM2 decryption")
    }
}

public func contractSm2EcdhSharedSecret(
    privateKey: Array<Byte>, peerPublicKey: Array<Byte>
): Array<Byte> {
    try {
        sm2EcdhSharedSecret(
            contractGmSm2PrivateKey(privateKey), sm2PublicKeyFromUncompressed(peerPublicKey)
        )
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, "SM2 ECDH")
    }
}

public func contractSm2InitiatorKeyExchange(
    staticPrivateKey: Array<Byte>,
    ephemeralPrivateKey: Array<Byte>,
    peerStaticPublicKey: Array<Byte>,
    peerEphemeralPublicKey: Array<Byte>,
    selfIdentity: Array<Byte>,
    peerIdentity: Array<Byte>,
    keyLen: Int64
): ContractSm2KeyExchangeResult {
    try {
        let result = sm2InitiatorKeyExchange(
            contractGmSm2PrivateKey(staticPrivateKey),
            contractGmSm2PrivateKey(ephemeralPrivateKey),
            sm2PublicKeyFromUncompressed(peerStaticPublicKey),
            sm2PublicKeyFromUncompressed(peerEphemeralPublicKey),
            selfIdentity, peerIdentity, keyLen
        )
        ContractSm2KeyExchangeResult(
            result.key, result.sendConfirmation, result.expectedPeerConfirmation
        )
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, "SM2 initiator key exchange")
    }
}

public func contractSm2ResponderKeyExchange(
    staticPrivateKey: Array<Byte>,
    ephemeralPrivateKey: Array<Byte>,
    peerStaticPublicKey: Array<Byte>,
    peerEphemeralPublicKey: Array<Byte>,
    selfIdentity: Array<Byte>,
    peerIdentity: Array<Byte>,
    keyLen: Int64
): ContractSm2KeyExchangeResult {
    try {
        let result = sm2ResponderKeyExchange(
            contractGmSm2PrivateKey(staticPrivateKey),
            contractGmSm2PrivateKey(ephemeralPrivateKey),
            sm2PublicKeyFromUncompressed(peerStaticPublicKey),
            sm2PublicKeyFromUncompressed(peerEphemeralPublicKey),
            selfIdentity, peerIdentity, keyLen
        )
        ContractSm2KeyExchangeResult(
            result.key, result.sendConfirmation, result.expectedPeerConfirmation
        )
    } catch (e: CryptoException) {
        throw contractGmPrimitiveException(e, "SM2 responder key exchange")
    }
}

public func contractSm2VerifyConfirmation(expected: Array<Byte>, received: Array<Byte>): Bool {
    sm2VerifyConfirmation(expected, received)
}

public class ContractSm3HashDrbg {
    private let context: Sm3HashDrbg

    public init(
        entropy: Array<Byte>, nonce: Array<Byte>, personalization!: Array<Byte> = []
    ) {
        try {
            context = Sm3HashDrbg(entropy, nonce, personalization: personalization)
        } catch (e: CryptoException) {
            throw contractGmPrimitiveException(e, "SM3 Hash-DRBG initialization")
        }
    }

    private init(context: Sm3HashDrbg) { this.context = context }

    public static func fromSystem(personalization!: Array<Byte> = []): ContractSm3HashDrbg {
        try {
            ContractSm3HashDrbg(sm3HashDrbgFromSystem(personalization: personalization))
        } catch (e: CryptoException) {
            throw contractGmPrimitiveException(e, "SM3 Hash-DRBG system initialization")
        }
    }

    public func generate(outputLen: Int64, additionalInput!: Array<Byte> = []): Array<Byte> {
        try {
            context.generateBytes(outputLen, additionalInput: additionalInput)
        } catch (e: CryptoException) {
            throw contractGmPrimitiveException(e, "SM3 Hash-DRBG generation")
        }
    }

    public func reseed(entropy: Array<Byte>, additionalInput!: Array<Byte> = []): Unit {
        try {
            context.reseed(entropy, additionalInput: additionalInput)
        } catch (e: CryptoException) {
            throw contractGmPrimitiveException(e, "SM3 Hash-DRBG reseed")
        }
    }

    public func reseedFromSystem(additionalInput!: Array<Byte> = []): Unit {
        try {
            context.reseedFromSystem(additionalInput: additionalInput)
        } catch (e: CryptoException) {
            throw contractGmPrimitiveException(e, "SM3 Hash-DRBG system reseed")
        }
    }

    public func reseedCounter(): UInt64 { context.reseedCounter() }
    public func uninstantiate(): Unit { context.uninstantiate() }
}

public class ContractSm4CtrDrbg {
    private let context: Sm4CtrDrbg

    public init(
        entropy: Array<Byte>, nonce: Array<Byte>, personalization!: Array<Byte> = []
    ) {
        try {
            context = Sm4CtrDrbg(entropy, nonce, personalization: personalization)
        } catch (e: CryptoException) {
            throw contractGmPrimitiveException(e, "SM4-CTR-DRBG initialization")
        }
    }

    private init(context: Sm4CtrDrbg) { this.context = context }

    public static func fromSystem(personalization!: Array<Byte> = []): ContractSm4CtrDrbg {
        try {
            ContractSm4CtrDrbg(sm4CtrDrbgFromSystem(personalization: personalization))
        } catch (e: CryptoException) {
            throw contractGmPrimitiveException(e, "SM4-CTR-DRBG system initialization")
        }
    }

    public func generate(outputLen: Int64, additionalInput!: Array<Byte> = []): Array<Byte> {
        try {
            context.generateBytes(outputLen, additionalInput: additionalInput)
        } catch (e: CryptoException) {
            throw contractGmPrimitiveException(e, "SM4-CTR-DRBG generation")
        }
    }

    public func reseed(entropy: Array<Byte>, additionalInput!: Array<Byte> = []): Unit {
        try {
            context.reseed(entropy, additionalInput: additionalInput)
        } catch (e: CryptoException) {
            throw contractGmPrimitiveException(e, "SM4-CTR-DRBG reseed")
        }
    }

    public func reseedFromSystem(additionalInput!: Array<Byte> = []): Unit {
        try {
            context.reseedFromSystem(additionalInput: additionalInput)
        } catch (e: CryptoException) {
            throw contractGmPrimitiveException(e, "SM4-CTR-DRBG system reseed")
        }
    }

    public func reseedCounter(): UInt64 { context.reseedCounter() }
    public func uninstantiate(): Unit { context.uninstantiate() }
}

private func contractGmSm2PrivateKey(encoded: Array<Byte>): Sm2PrivateKey {
    contractGmRequireSize(encoded, CONTRACT_SM2_PRIVATE_KEY_LEN, "SM2 private key")
    Sm2PrivateKey(BigNum.fromBytesBE(encoded))
}

private func contractGmRequireSize(value: Array<Byte>, expected: Int64, label: String): Unit {
    if (value.size != expected) {
        throw ContractException(
            ContractErrorCode.BadInput, "${label} must be ${expected} bytes"
        )
    }
}

private func contractGmConcat(values: Array<Array<Byte>>): Array<Byte> {
    var size: Int64 = 0
    for (value in values) { size += value.size }
    let output = Array<Byte>(size, repeat: UInt8(0))
    var offset: Int64 = 0
    for (value in values) {
        var i: Int64 = 0
        while (i < value.size) {
            output[offset + i] = value[i]
            i += 1
        }
        offset += value.size
    }
    output
}

private func contractGmPrimitiveException(
    error: CryptoException, operation: String
): ContractException {
    let code = match (error.code) {
        case CryptoErrorCode.InvalidArgument => ContractErrorCode.BadInput
        case CryptoErrorCode.OutOfBounds => ContractErrorCode.BadInput
        case CryptoErrorCode.DivideByZero => ContractErrorCode.BadInput
        case CryptoErrorCode.NoModInverse => ContractErrorCode.BadInput
        case CryptoErrorCode.ParseError => ContractErrorCode.BadInput
        case CryptoErrorCode.ComplianceRejected => ContractErrorCode.ComplianceRejected
        case CryptoErrorCode.Unsupported => ContractErrorCode.Unsupported
        case CryptoErrorCode.InternalError => ContractErrorCode.InternalError
        case _ => ContractErrorCode.InternalError
    }
    ContractException(code, "${operation} failed: ${error.message}")
}
