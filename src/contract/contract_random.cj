package jinguissl.contract

import jinguissl_core.crypto.error.{CryptoErrorCode, CryptoException}
import jinguissl_core.crypto.utils.{csprngBytes, csprngIsAvailable}

/** Fail-closed system CSPRNG output on the preferred Contract package. */
public func contractRandomBytes(size: Int64): Array<Byte> {
    if (size <= 0) {
        throw ContractException(ContractErrorCode.BadInput, "random byte size must be > 0")
    }
    if (!csprngIsAvailable()) {
        throw ContractException(ContractErrorCode.CryptoUnavailable, "system CSPRNG is unavailable")
    }
    try {
        csprngBytes(size)
    } catch (e: CryptoException) {
        let code = if (e.code == CryptoErrorCode.Unsupported) {
            ContractErrorCode.CryptoUnavailable
        } else {
            contractMapCoreCryptoException(e)
        }
        throw ContractException(
            code,
            "random generation failed: ${e.message}"
        )
    }
}
