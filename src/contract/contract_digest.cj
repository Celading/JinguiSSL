package jinguissl.contract

import jinguissl_core.crypto.digest.{hash, md5, sha1, sha256, sha384, sha512, bytesToHexLower, hmac, hkdfExtract, hkdfExpand, hkdf}
import jinguissl_core.crypto.digest.HashAlgorithm as CoreHashAlgorithm

/**
 * Contract-owned digest selection. No Core-owned enum crosses public APIs.
 */
public enum HashAlgorithm <: Equatable<HashAlgorithm> & ToString {
    | MD5
    | SHA1
    | SHA256
    | SHA384
    | SHA512
    | SM3

    public operator func ==(right: HashAlgorithm): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: HashAlgorithm): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case MD5 => 0
            case SHA1 => 1
            case SHA256 => 2
            case SHA384 => 3
            case SHA512 => 4
            case SM3 => 5
        }
    }

    public func toString(): String {
        match (this) {
            case MD5 => "MD5"
            case SHA1 => "SHA-1"
            case SHA256 => "SHA-256"
            case SHA384 => "SHA-384"
            case SHA512 => "SHA-512"
            case SM3 => "SM3"
        }
    }
}

/**
 * contractHash — generic hash dispatcher.
 * Delegates to core's hash().
 */
public func contractHash(algorithm: HashAlgorithm, data: Array<Byte>): Array<Byte> {
    hash(contractCoreHashAlgorithm(algorithm), data)
}

/**
 * contractMd5 — MD5 hash.
 * @deprecated MD5 is cryptographically broken. Only for legacy compatibility.
 */
public func contractMd5(data: Array<Byte>): Array<Byte> {
    md5(data)
}

/**
 * contractSha1 — SHA-1 hash.
 * @deprecated SHA-1 is cryptographically broken. Use SHA-256 or higher.
 */
public func contractSha1(data: Array<Byte>): Array<Byte> {
    sha1(data)
}

/**
 * contractSha256 — SHA-256 hash.
 */
public func contractSha256(data: Array<Byte>): Array<Byte> {
    sha256(data)
}

/**
 * contractSha384 — SHA-384 hash.
 */
public func contractSha384(data: Array<Byte>): Array<Byte> {
    sha384(data)
}

/**
 * contractSha512 — SHA-512 hash.
 */
public func contractSha512(data: Array<Byte>): Array<Byte> {
    sha512(data)
}

/**
 * contractBytesToHexLower — byte array to lowercase hex string.
 */
public func contractBytesToHexLower(bytes: Array<Byte>): String {
    bytesToHexLower(bytes)
}

/**
 * contractHmac — HMAC with given hash algorithm.
 */
public func contractHmac(algorithm: HashAlgorithm, key: Array<Byte>, data: Array<Byte>): Array<Byte> {
    hmac(contractCoreHashAlgorithm(algorithm), key, data)
}

/**
 * contractHkdfExtract — HKDF extract step.
 */
public func contractHkdfExtract(
    algorithm: HashAlgorithm,
    salt: Array<Byte>,
    ikm: Array<Byte>
): Array<Byte> {
    hkdfExtract(contractCoreHashAlgorithm(algorithm), salt, ikm)
}

/**
 * contractHkdfExpand — HKDF expand step.
 */
public func contractHkdfExpand(
    algorithm: HashAlgorithm,
    prk: Array<Byte>,
    info: Array<Byte>,
    outputLen: Int64
): Array<Byte> {
    hkdfExpand(contractCoreHashAlgorithm(algorithm), prk, info, outputLen)
}

/**
 * contractHkdf — full HKDF (extract then expand).
 */
public func contractHkdf(
    algorithm: HashAlgorithm,
    ikm: Array<Byte>,
    info: Array<Byte>,
    outputLen: Int64,
    salt!: Array<Byte> = []
): Array<Byte> {
    hkdf(contractCoreHashAlgorithm(algorithm), ikm, info, outputLen, salt: salt)
}

internal func contractCoreHashAlgorithm(algorithm: HashAlgorithm): CoreHashAlgorithm {
    match (algorithm) {
        case HashAlgorithm.MD5 => CoreHashAlgorithm.MD5
        case HashAlgorithm.SHA1 => CoreHashAlgorithm.SHA1
        case HashAlgorithm.SHA256 => CoreHashAlgorithm.SHA256
        case HashAlgorithm.SHA384 => CoreHashAlgorithm.SHA384
        case HashAlgorithm.SHA512 => CoreHashAlgorithm.SHA512
        case HashAlgorithm.SM3 => CoreHashAlgorithm.SM3
    }
}
