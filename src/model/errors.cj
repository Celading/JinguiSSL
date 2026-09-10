protected package jinguissl.model

public enum ContractErrorCode <: Equatable<ContractErrorCode> & ToString {
    | BadInput
    | KeyNotFound
    | VerifyFailed
    | CryptoUnavailable
    | ComplianceRejected
    | Unsupported
    | InternalError

    public operator func ==(right: ContractErrorCode): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: ContractErrorCode): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case BadInput => 0
            case KeyNotFound => 1
            case VerifyFailed => 2
            case CryptoUnavailable => 3
            case ComplianceRejected => 4
            case Unsupported => 5
            case InternalError => 6
        }
    }

    public func toString(): String {
        match (this) {
            case BadInput => "BAD_INPUT"
            case KeyNotFound => "KEY_NOT_FOUND"
            case VerifyFailed => "VERIFY_FAILED"
            case CryptoUnavailable => "CRYPTO_UNAVAILABLE"
            case ComplianceRejected => "COMPLIANCE_REJECTED"
            case Unsupported => "UNSUPPORTED"
            case InternalError => "INTERNAL_ERROR"
        }
    }
}

public class ContractException <: Exception {
    public let code: ContractErrorCode

    public init(code: ContractErrorCode, message: String) {
        super(message)
        this.code = code
    }
}

public enum ContractIgniteCryptoErrorCode <: Equatable<ContractIgniteCryptoErrorCode> & ToString {
    | BadEnvelope
    | KeyNotFound
    | DecryptFailed
    | CryptoUnavailable

    public operator func ==(right: ContractIgniteCryptoErrorCode): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: ContractIgniteCryptoErrorCode): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case BadEnvelope => 0
            case KeyNotFound => 1
            case DecryptFailed => 2
            case CryptoUnavailable => 3
        }
    }

    public func toString(): String {
        match (this) {
            case BadEnvelope => "BAD_ENVELOPE"
            case KeyNotFound => "KEY_NOT_FOUND"
            case DecryptFailed => "DECRYPT_FAILED"
            case CryptoUnavailable => "CRYPTO_UNAVAILABLE"
        }
    }
}
