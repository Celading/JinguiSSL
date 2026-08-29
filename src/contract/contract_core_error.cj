package jinguissl.contract

import jinguissl_core.crypto.error.{CryptoErrorCode, CryptoException}

internal func contractMapCoreCryptoException(
    exception: CryptoException,
    verificationFailure!: Bool = false
): ContractErrorCode {
    if (verificationFailure) {
        if (
            exception.code == CryptoErrorCode.InvalidArgument ||
            exception.code == CryptoErrorCode.ParseError
        ) {
            return ContractErrorCode.VerifyFailed
        }
    }
    match (exception.code) {
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
}
