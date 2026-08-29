package jinguissl.contract

import jinguissl_core.crypto.aes.{
    aesEcbEncrypt,
    aesEcbDecrypt,
    aesCbcEncrypt,
    aesCbcDecrypt,
    aesCtrCrypt,
    aesGcmEncrypt,
    aesGcmDecrypt
}
import jinguissl_core.crypto.error.CryptoException

public enum ContractAesMode <: Equatable<ContractAesMode> & ToString {
    | AesEcb
    | AesCbc
    | AesCtr

    public operator func ==(right: ContractAesMode): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case AesEcb => 0
            case AesCbc => 1
            case AesCtr => 2
        }
    }

    public func toString(): String {
        match (this) {
            case AesEcb => "AES-ECB"
            case AesCbc => "AES-CBC"
            case AesCtr => "AES-CTR"
        }
    }
}

public class ContractAesGcmResult {
    public let ciphertext: Array<Byte>
    public let tag: Array<Byte>

    public init(ciphertext: Array<Byte>, tag: Array<Byte>) {
        if (tag.size < 4 || tag.size > 16) {
            throw ContractException(ContractErrorCode.BadInput, "AES-GCM tag must be 4..16 bytes")
        }
        this.ciphertext = ciphertext.clone()
        this.tag = tag.clone()
    }
}

public func contractAesEncrypt(
    mode: ContractAesMode,
    key: Array<Byte>,
    input: Array<Byte>,
    parameter!: Array<Byte> = [],
    pkcs7!: Bool = false
): Array<Byte> {
    contractValidateAesOperation(mode, key, parameter, pkcs7)
    try {
        match (mode) {
            case AesEcb => aesEcbEncrypt(key, input, pkcs7: pkcs7)
            case AesCbc => aesCbcEncrypt(key, parameter, input, pkcs7: pkcs7)
            case AesCtr => aesCtrCrypt(key, parameter, input)
        }
    } catch (e: CryptoException) {
        throw contractAesPrimitiveException(e, mode.toString() + " encryption")
    }
}

public func contractAesDecrypt(
    mode: ContractAesMode,
    key: Array<Byte>,
    input: Array<Byte>,
    parameter!: Array<Byte> = [],
    pkcs7!: Bool = false
): Array<Byte> {
    contractValidateAesOperation(mode, key, parameter, pkcs7)
    try {
        match (mode) {
            case AesEcb => aesEcbDecrypt(key, input, pkcs7: pkcs7)
            case AesCbc => aesCbcDecrypt(key, parameter, input, pkcs7: pkcs7)
            case AesCtr => aesCtrCrypt(key, parameter, input)
        }
    } catch (e: CryptoException) {
        throw contractAesPrimitiveException(e, mode.toString() + " decryption")
    }
}

public func contractAesGcmEncrypt(
    key: Array<Byte>,
    nonce: Array<Byte>,
    plaintext: Array<Byte>,
    aad!: Array<Byte> = [],
    tagLen!: Int64 = 16
): ContractAesGcmResult {
    contractValidateAesKey(key)
    if (nonce.size == 0 || tagLen < 4 || tagLen > 16) {
        throw ContractException(
            ContractErrorCode.BadInput,
            "AES-GCM nonce must not be empty and tag must be 4..16 bytes"
        )
    }
    try {
        let (ciphertext, tag) = aesGcmEncrypt(key, nonce, plaintext, aad: aad, tagLen: tagLen)
        ContractAesGcmResult(ciphertext, tag)
    } catch (e: CryptoException) {
        throw contractAesPrimitiveException(e, "AES-GCM encryption")
    }
}

public func contractAesGcmDecrypt(
    key: Array<Byte>,
    nonce: Array<Byte>,
    ciphertext: Array<Byte>,
    tag: Array<Byte>,
    aad!: Array<Byte> = []
): Array<Byte> {
    contractValidateAesKey(key)
    if (nonce.size == 0 || tag.size < 4 || tag.size > 16) {
        throw ContractException(
            ContractErrorCode.BadInput,
            "AES-GCM nonce must not be empty and tag must be 4..16 bytes"
        )
    }
    try {
        aesGcmDecrypt(key, nonce, ciphertext, tag, aad: aad)
    } catch (e: CryptoException) {
        throw ContractException(
            contractMapCoreCryptoException(e, verificationFailure: true),
            "AES-GCM decryption failed: ${e.message}"
        )
    }
}

private func contractValidateAesOperation(
    mode: ContractAesMode,
    key: Array<Byte>,
    parameter: Array<Byte>,
    pkcs7: Bool
): Unit {
    contractValidateAesKey(key)
    match (mode) {
        case AesEcb =>
            if (parameter.size != 0) {
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "AES-ECB does not accept an IV/counter parameter"
                )
            }
        case AesCbc =>
            if (parameter.size != 16) {
                throw ContractException(ContractErrorCode.BadInput, "AES-CBC IV must be 16 bytes")
            }
        case AesCtr =>
            if (parameter.size != 16 || pkcs7) {
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "AES-CTR counter must be 16 bytes and PKCS#7 is not applicable"
                )
            }
    }
}

private func contractValidateAesKey(key: Array<Byte>): Unit {
    if (key.size != 16 && key.size != 24 && key.size != 32) {
        throw ContractException(
            ContractErrorCode.BadInput,
            "AES key must be 16, 24 or 32 bytes"
        )
    }
}

private func contractAesPrimitiveException(
    exception: CryptoException, operation: String
): ContractException {
    ContractException(
        contractMapCoreCryptoException(exception),
        "${operation} failed: ${exception.message}"
    )
}
