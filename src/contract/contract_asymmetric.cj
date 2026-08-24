package jinguissl.contract

import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.digest.hash
import jinguissl_core.crypto.digest.HashAlgorithm as CoreHashAlgorithm
import jinguissl_core.crypto.ecc.{
    NamedCurve,
    EcPrivateKey,
    EcPublicKey,
    Es256P256StructuredVerifyRequest,
    ecPublicFromPrivateKey,
    ecdhDeriveSharedSecret,
    ecdsaSign,
    ecdsaVerify,
    es256P256VerifyStructuredRequest
}
import jinguissl_core.crypto.ed25519.{
    ed25519GeneratePrivateKeySeed,
    ed25519PublicKeyFromSeed,
    ed25519Sign,
    ed25519Verify
}
import jinguissl_core.crypto.error.{CryptoErrorCode, CryptoException}
import jinguissl_core.crypto.rsa.{
    RsaHashAlgorithm,
    RsaPrivateKey,
    RsaPublicKey,
    rsaGenerateKey,
    rsaSignPkcs1v15WithHash,
    rsaVerifyPkcs1v15WithHash,
    rsaSignPssWithHash,
    rsaVerifyPssWithHash
}
import jinguissl_core.crypto.utils.randomSeed

public enum ContractSignatureHash <: Equatable<ContractSignatureHash> & ToString {
    | Sha256
    | Sha384
    | Sha512

    public operator func ==(right: ContractSignatureHash): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case Sha256 => 0
            case Sha384 => 1
            case Sha512 => 2
        }
    }

    public func toString(): String {
        match (this) {
            case Sha256 => "SHA-256"
            case Sha384 => "SHA-384"
            case Sha512 => "SHA-512"
        }
    }
}

public enum ContractEcCurve <: Equatable<ContractEcCurve> & ToString {
    | P256
    | P384
    | P521
    | Secp256k1

    public operator func ==(right: ContractEcCurve): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case P256 => 0
            case P384 => 1
            case P521 => 2
            case Secp256k1 => 3
        }
    }

    public func fieldLen(): Int64 {
        match (this) {
            case P256 => 32
            case P384 => 48
            case P521 => 66
            case Secp256k1 => 32
        }
    }

    public func toString(): String {
        match (this) {
            case P256 => "P-256"
            case P384 => "P-384"
            case P521 => "P-521"
            case Secp256k1 => "secp256k1"
        }
    }
}

public class ContractEcPublicKey {
    public let curve: ContractEcCurve
    public let uncompressed: Array<Byte>

    public init(curve: ContractEcCurve, uncompressed: Array<Byte>) {
        if (
            uncompressed.size != 1 + (2 * curve.fieldLen()) ||
            UInt8(uncompressed[0]) != UInt8(0x04)
        ) {
            throw ContractException(ContractErrorCode.BadInput, "EC public key encoding is invalid")
        }
        this.curve = curve
        this.uncompressed = uncompressed.clone()
    }
}

public class ContractEcKeyPair {
    public let curve: ContractEcCurve
    public let privateKey: Array<Byte>
    public let publicKey: ContractEcPublicKey

    public init(
        curve: ContractEcCurve, privateKey: Array<Byte>, publicKey: ContractEcPublicKey
    ) {
        if (privateKey.size != curve.fieldLen() || publicKey.curve != curve) {
            throw ContractException(ContractErrorCode.BadInput, "EC keypair shape is invalid")
        }
        try {
            let derived = contractEcPublicKey(
                ecPublicFromPrivateKey(contractEcPrivateKey(curve, privateKey))
            )
            if (derived.uncompressed != publicKey.uncompressed) {
                throw ContractException(
                    ContractErrorCode.VerifyFailed,
                    "EC keypair public key does not match the private key"
                )
            }
        } catch (e: CryptoException) {
            throw contractAsymmetricException(e, "EC keypair validation")
        }
        this.curve = curve
        this.privateKey = privateKey.clone()
        this.publicKey = publicKey
    }
}

public class ContractEcSignature {
    public let curve: ContractEcCurve
    public let encoded: Array<Byte>

    public init(curve: ContractEcCurve, encoded: Array<Byte>) {
        if (encoded.size != 2 * curve.fieldLen()) {
            throw ContractException(ContractErrorCode.BadInput, "ECDSA signature shape is invalid")
        }
        this.curve = curve
        this.encoded = encoded.clone()
    }
}

public func contractEcGenerateKeyPair(curve: ContractEcCurve): ContractEcKeyPair {
    var attempt: Int64 = 0
    while (attempt < 64) {
        var privateBytes: Array<Byte> = []
        try {
            privateBytes = randomSeed(size: curve.fieldLen())
        } catch (e: CryptoException) {
            throw contractAsymmetricException(e, "EC key generation entropy")
        }
        try {
            let privateKey = contractEcPrivateKey(curve, privateBytes)
            let publicKey = contractEcPublicKey(ecPublicFromPrivateKey(privateKey))
            return ContractEcKeyPair(curve, privateBytes, publicKey)
        } catch (_: CryptoException) {
            attempt += 1
        }
    }
    throw ContractException(ContractErrorCode.InternalError, "EC key generation exceeded attempt budget")
}

public func contractEcPublicFromPrivate(
    curve: ContractEcCurve, privateKey: Array<Byte>
): ContractEcPublicKey {
    try {
        contractEcPublicKey(ecPublicFromPrivateKey(contractEcPrivateKey(curve, privateKey)))
    } catch (e: CryptoException) {
        throw contractAsymmetricException(e, "EC public-key derivation")
    }
}

public func contractEcdsaSign(
    curve: ContractEcCurve,
    privateKey: Array<Byte>,
    message: Array<Byte>,
    hashAlgorithm!: ContractSignatureHash = ContractSignatureHash.Sha256
): ContractEcSignature {
    try {
        let (r, s) = ecdsaSign(
            contractEcPrivateKey(curve, privateKey),
            hash(contractCoreHash(hashAlgorithm), message)
        )
        let width = curve.fieldLen()
        let encoded = Array<Byte>(2 * width, repeat: 0)
        contractCopyBytes(r.toBytesBE(paddedLen: width), encoded, 0)
        contractCopyBytes(s.toBytesBE(paddedLen: width), encoded, width)
        ContractEcSignature(curve, encoded)
    } catch (e: CryptoException) {
        throw contractAsymmetricException(e, "ECDSA signing")
    }
}

public func contractEcdsaVerify(
    publicKey: ContractEcPublicKey,
    message: Array<Byte>,
    signature: ContractEcSignature,
    hashAlgorithm!: ContractSignatureHash = ContractSignatureHash.Sha256
): Bool {
    if (publicKey.curve != signature.curve) {
        return false
    }
    try {
        let width = publicKey.curve.fieldLen()
        ecdsaVerify(
            contractEcCorePublicKey(publicKey),
            hash(contractCoreHash(hashAlgorithm), message),
            BigNum.fromBytesBE(signature.encoded[..width]),
            BigNum.fromBytesBE(signature.encoded[width..])
        )
    } catch (e: CryptoException) {
        throw contractAsymmetricException(e, "ECDSA verification")
    }
}

public func contractEs256VerifyDer(
    publicKey: ContractEcPublicKey,
    signedBytes: Array<Byte>,
    derSignature: Array<Byte>
): Bool {
    if (publicKey.curve != ContractEcCurve.P256) {
        throw ContractException(ContractErrorCode.Unsupported, "ES256 requires P-256")
    }
    try {
        let width = publicKey.curve.fieldLen()
        let result = es256P256VerifyStructuredRequest(
            Es256P256StructuredVerifyRequest(
                publicKey.uncompressed[1..(1 + width)],
                publicKey.uncompressed[(1 + width)..],
                signedBytes,
                derSignature
            )
        )
        result.signatureVerified
    } catch (e: CryptoException) {
        throw contractAsymmetricException(e, "ES256 structured verification")
    }
}

public func contractEcdh(
    curve: ContractEcCurve,
    privateKey: Array<Byte>,
    peerPublicKey: ContractEcPublicKey
): Array<Byte> {
    if (curve != peerPublicKey.curve) {
        throw ContractException(ContractErrorCode.BadInput, "ECDH curve mismatch")
    }
    try {
        ecdhDeriveSharedSecret(
            contractEcPrivateKey(curve, privateKey), contractEcCorePublicKey(peerPublicKey)
        )
    } catch (e: CryptoException) {
        throw contractAsymmetricException(e, "ECDH key agreement")
    }
}

public class ContractEd25519KeyPair {
    public let privateKeySeed: Array<Byte>
    public let publicKey: Array<Byte>

    public init(privateKeySeed: Array<Byte>, publicKey: Array<Byte>) {
        if (privateKeySeed.size != 32 || publicKey.size != 32) {
            throw ContractException(ContractErrorCode.BadInput, "Ed25519 key shape is invalid")
        }
        try {
            if (ed25519PublicKeyFromSeed(privateKeySeed) != publicKey) {
                throw ContractException(
                    ContractErrorCode.VerifyFailed,
                    "Ed25519 public key does not match the private seed"
                )
            }
        } catch (e: CryptoException) {
            throw contractAsymmetricException(e, "Ed25519 keypair validation")
        }
        this.privateKeySeed = privateKeySeed.clone()
        this.publicKey = publicKey.clone()
    }
}

public func contractEd25519GenerateKeyPair(): ContractEd25519KeyPair {
    try {
        let seed = ed25519GeneratePrivateKeySeed()
        ContractEd25519KeyPair(seed, ed25519PublicKeyFromSeed(seed))
    } catch (e: CryptoException) {
        throw contractAsymmetricException(e, "Ed25519 key generation")
    }
}

public func contractEd25519PublicFromSeed(privateKeySeed: Array<Byte>): Array<Byte> {
    try {
        ed25519PublicKeyFromSeed(privateKeySeed)
    } catch (e: CryptoException) {
        throw contractAsymmetricException(e, "Ed25519 public-key derivation")
    }
}

public func contractEd25519Sign(
    privateKeySeed: Array<Byte>, message: Array<Byte>
): Array<Byte> {
    try {
        ed25519Sign(privateKeySeed, message)
    } catch (e: CryptoException) {
        throw contractAsymmetricException(e, "Ed25519 signing")
    }
}

public func contractEd25519Verify(
    publicKey: Array<Byte>, message: Array<Byte>, signature: Array<Byte>
): Bool {
    try {
        ed25519Verify(publicKey, message, signature)
    } catch (e: CryptoException) {
        throw contractAsymmetricException(e, "Ed25519 verification")
    }
}

public enum ContractRsaSignatureScheme <: Equatable<ContractRsaSignatureScheme> & ToString {
    | Pss
    | Pkcs1v15

    public operator func ==(right: ContractRsaSignatureScheme): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case Pss => 0
            case Pkcs1v15 => 1
        }
    }

    public func toString(): String {
        match (this) {
            case Pss => "RSA-PSS"
            case Pkcs1v15 => "RSA-PKCS1V1.5"
        }
    }
}

public class ContractRsaPublicKey {
    public let modulus: Array<Byte>
    public let publicExponent: Array<Byte>

    public init(modulus: Array<Byte>, publicExponent: Array<Byte>) {
        if (modulus.size == 0 || publicExponent.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "RSA public key fields must not be empty")
        }
        this.modulus = modulus.clone()
        this.publicExponent = publicExponent.clone()
        try {
            _ = contractRsaCorePublicKey(this)
        } catch (e: CryptoException) {
            throw contractAsymmetricException(e, "RSA public-key validation")
        }
    }

    public func bits(): Int64 { contractRsaCorePublicKey(this).bits() }
}

public class ContractRsaPrivateKey {
    public let publicKey: ContractRsaPublicKey
    public let privateExponent: Array<Byte>

    public init(publicKey: ContractRsaPublicKey, privateExponent: Array<Byte>) {
        if (privateExponent.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "RSA private exponent must not be empty")
        }
        this.publicKey = publicKey
        this.privateExponent = privateExponent.clone()
        try {
            _ = contractRsaCorePrivateKey(this)
        } catch (e: CryptoException) {
            throw contractAsymmetricException(e, "RSA private-key validation")
        }
    }
}

public func contractRsaGenerateKeyPair(bits: Int64): ContractRsaPrivateKey {
    try {
        contractRsaPrivateKey(rsaGenerateKey(bits))
    } catch (e: CryptoException) {
        throw contractAsymmetricException(e, "RSA key generation")
    }
}

public func contractRsaSign(
    privateKey: ContractRsaPrivateKey,
    message: Array<Byte>,
    scheme!: ContractRsaSignatureScheme = ContractRsaSignatureScheme.Pss,
    hashAlgorithm!: ContractSignatureHash = ContractSignatureHash.Sha256,
    saltLen!: Int64 = -1
): Array<Byte> {
    try {
        let digest = hash(contractCoreHash(hashAlgorithm), message)
        match (scheme) {
            case Pss => rsaSignPssWithHash(
                contractRsaCorePrivateKey(privateKey),
                digest,
                contractCoreRsaHash(hashAlgorithm),
                saltLen: saltLen
            )
            case Pkcs1v15 => rsaSignPkcs1v15WithHash(
                contractRsaCorePrivateKey(privateKey),
                digest,
                contractCoreRsaHash(hashAlgorithm)
            )
        }
    } catch (e: CryptoException) {
        throw contractAsymmetricException(e, scheme.toString() + " signing")
    }
}

public func contractRsaVerify(
    publicKey: ContractRsaPublicKey,
    message: Array<Byte>,
    signature: Array<Byte>,
    scheme!: ContractRsaSignatureScheme = ContractRsaSignatureScheme.Pss,
    hashAlgorithm!: ContractSignatureHash = ContractSignatureHash.Sha256,
    saltLen!: Int64 = -1
): Bool {
    try {
        let digest = hash(contractCoreHash(hashAlgorithm), message)
        match (scheme) {
            case Pss => rsaVerifyPssWithHash(
                contractRsaCorePublicKey(publicKey),
                digest,
                signature,
                contractCoreRsaHash(hashAlgorithm),
                saltLen: saltLen
            )
            case Pkcs1v15 => rsaVerifyPkcs1v15WithHash(
                contractRsaCorePublicKey(publicKey),
                digest,
                signature,
                contractCoreRsaHash(hashAlgorithm)
            )
        }
    } catch (e: CryptoException) {
        throw contractAsymmetricException(e, scheme.toString() + " verification")
    }
}

internal func contractEcPrivateKey(
    curve: ContractEcCurve, encoded: Array<Byte>
): EcPrivateKey {
    if (encoded.size != curve.fieldLen()) {
        throw CryptoException(CryptoErrorCode.InvalidArgument, "EC private-key length mismatch")
    }
    EcPrivateKey(contractCoreCurve(curve), BigNum.fromBytesBE(encoded))
}

internal func contractEcCorePublicKey(publicKey: ContractEcPublicKey): EcPublicKey {
    let width = publicKey.curve.fieldLen()
    EcPublicKey(
        contractCoreCurve(publicKey.curve),
        BigNum.fromBytesBE(publicKey.uncompressed[1..(1 + width)]),
        BigNum.fromBytesBE(publicKey.uncompressed[(1 + width)..])
    )
}

internal func contractEcPublicKey(publicKey: EcPublicKey): ContractEcPublicKey {
    let curve = contractEcCurve(publicKey.curve)
    let width = curve.fieldLen()
    let encoded = Array<Byte>(1 + (2 * width), repeat: 0)
    encoded[0] = UInt8(0x04)
    contractCopyBytes(publicKey.x.toBytesBE(paddedLen: width), encoded, 1)
    contractCopyBytes(publicKey.y.toBytesBE(paddedLen: width), encoded, 1 + width)
    ContractEcPublicKey(curve, encoded)
}

internal func contractRsaCorePublicKey(key: ContractRsaPublicKey): RsaPublicKey {
    RsaPublicKey(BigNum.fromBytesBE(key.modulus), BigNum.fromBytesBE(key.publicExponent))
}

internal func contractRsaCorePrivateKey(key: ContractRsaPrivateKey): RsaPrivateKey {
    RsaPrivateKey(
        BigNum.fromBytesBE(key.publicKey.modulus),
        BigNum.fromBytesBE(key.publicKey.publicExponent),
        BigNum.fromBytesBE(key.privateExponent)
    )
}

internal func contractRsaPrivateKey(key: RsaPrivateKey): ContractRsaPrivateKey {
    ContractRsaPrivateKey(
        ContractRsaPublicKey(
            key.publicKey.modulus.toBytesBE(), key.publicKey.exponent.toBytesBE()
        ),
        key.privateExponent.toBytesBE()
    )
}

private func contractCoreCurve(curve: ContractEcCurve): NamedCurve {
    match (curve) {
        case P256 => NamedCurve.P256
        case P384 => NamedCurve.P384
        case P521 => NamedCurve.P521
        case Secp256k1 => NamedCurve.SECP256K1
    }
}

private func contractEcCurve(curve: NamedCurve): ContractEcCurve {
    match (curve) {
        case P256 => ContractEcCurve.P256
        case P384 => ContractEcCurve.P384
        case P521 => ContractEcCurve.P521
        case SECP256K1 => ContractEcCurve.Secp256k1
    }
}

private func contractCoreHash(hashAlgorithm: ContractSignatureHash): CoreHashAlgorithm {
    match (hashAlgorithm) {
        case Sha256 => CoreHashAlgorithm.SHA256
        case Sha384 => CoreHashAlgorithm.SHA384
        case Sha512 => CoreHashAlgorithm.SHA512
    }
}

private func contractCoreRsaHash(hashAlgorithm: ContractSignatureHash): RsaHashAlgorithm {
    match (hashAlgorithm) {
        case Sha256 => RsaHashAlgorithm.SHA256
        case Sha384 => RsaHashAlgorithm.SHA384
        case Sha512 => RsaHashAlgorithm.SHA512
    }
}

private func contractCopyBytes(source: Array<Byte>, destination: Array<Byte>, offset: Int64): Unit {
    var i: Int64 = 0
    while (i < source.size) {
        destination[offset + i] = source[i]
        i += 1
    }
}

private func contractAsymmetricException(
    exception: CryptoException, operation: String
): ContractException {
    ContractException(
        contractMapCoreCryptoException(exception),
        "${operation} failed: ${exception.message}"
    )
}
