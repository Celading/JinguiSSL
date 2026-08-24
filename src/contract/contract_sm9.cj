package jinguissl.contract

import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.error.{CryptoErrorCode, CryptoException}
import jinguissl_core.crypto.sm9.*

public let CONTRACT_SM9_SCALAR_LEN: Int64 = 32
public let CONTRACT_SM9_G1_LEN: Int64 = 64
public let CONTRACT_SM9_G2_LEN: Int64 = 128
public let CONTRACT_SM9_SIGNATURE_LEN: Int64 = 96
public let CONTRACT_SM9_PAIRING_LEN: Int64 = 384

public class ContractSm9SignMasterKeyPair {
    public let privateKey: Array<Byte>
    public let publicKey: Array<Byte>

    public init(privateKey: Array<Byte>, publicKey: Array<Byte>) {
        contractSm9RequireSize(privateKey, CONTRACT_SM9_SCALAR_LEN, "SM9 signing master private key")
        contractSm9RequireSize(publicKey, CONTRACT_SM9_G2_LEN, "SM9 signing master public key")
        this.privateKey = privateKey.clone()
        this.publicKey = publicKey.clone()
    }
}

public class ContractSm9SignUserPrivateKey {
    public let privateKey: Array<Byte>
    public let masterPublicKey: Array<Byte>

    public init(privateKey: Array<Byte>, masterPublicKey: Array<Byte>) {
        contractSm9RequireSize(privateKey, CONTRACT_SM9_G1_LEN, "SM9 signing user private key")
        contractSm9RequireSize(masterPublicKey, CONTRACT_SM9_G2_LEN, "SM9 signing master public key")
        this.privateKey = privateKey.clone()
        this.masterPublicKey = masterPublicKey.clone()
    }
}

public class ContractSm9EncryptionMasterKeyPair {
    public let privateKey: Array<Byte>
    public let publicKey: Array<Byte>

    public init(privateKey: Array<Byte>, publicKey: Array<Byte>) {
        contractSm9RequireSize(privateKey, CONTRACT_SM9_SCALAR_LEN, "SM9 encryption master private key")
        contractSm9RequireSize(publicKey, CONTRACT_SM9_G1_LEN, "SM9 encryption master public key")
        this.privateKey = privateKey.clone()
        this.publicKey = publicKey.clone()
    }
}

public class ContractSm9EncryptionUserPrivateKey {
    public let privateKey: Array<Byte>
    public let masterPublicKey: Array<Byte>

    public init(privateKey: Array<Byte>, masterPublicKey: Array<Byte>) {
        contractSm9RequireSize(privateKey, CONTRACT_SM9_G2_LEN, "SM9 encryption user private key")
        contractSm9RequireSize(masterPublicKey, CONTRACT_SM9_G1_LEN, "SM9 encryption master public key")
        this.privateKey = privateKey.clone()
        this.masterPublicKey = masterPublicKey.clone()
    }
}

public class ContractSm9KeyExchangeResult {
    public let key: Array<Byte>
    public let sendConfirmation: Array<Byte>
    public let expectedPeerConfirmation: Array<Byte>

    public init(
        key: Array<Byte>, sendConfirmation: Array<Byte>, expectedPeerConfirmation: Array<Byte>
    ) {
        if (key.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "SM9 shared key must not be empty")
        }
        contractSm9RequireSize(sendConfirmation, 32, "SM9 send confirmation")
        contractSm9RequireSize(expectedPeerConfirmation, 32, "SM9 peer confirmation")
        this.key = key.clone()
        this.sendConfirmation = sendConfirmation.clone()
        this.expectedPeerConfirmation = expectedPeerConfirmation.clone()
    }
}

/** Opaque retained SM9 exchange state; only the encoded ephemeral public key is exposed. */
public class ContractSm9KeyExchangeState {
    private let coreState: Sm9KeyExchangeState
    public let ephemeralPublicKey: Array<Byte>

    internal init(coreState: Sm9KeyExchangeState) {
        this.coreState = coreState
        this.ephemeralPublicKey = sm9G1PointToBytes(coreState.ephemeralPublic)
    }

    internal func complete(
        peerEphemeralPublicKey: Array<Byte>, initiator: Bool, keyLen: Int64
    ): ContractSm9KeyExchangeResult {
        let result = sm9CompleteKeyExchange(
            coreState, sm9G1PointFromBytes(peerEphemeralPublicKey), initiator, keyLen
        )
        ContractSm9KeyExchangeResult(
            result.key, result.sendConfirmation, result.expectedPeerConfirmation
        )
    }
}

public func contractSm9HashH1(input: Array<Byte>): Array<Byte> {
    sm9HashH1(input).toBytesBE(paddedLen: CONTRACT_SM9_SCALAR_LEN)
}

public func contractSm9HashH2(input: Array<Byte>): Array<Byte> {
    sm9HashH2(input).toBytesBE(paddedLen: CONTRACT_SM9_SCALAR_LEN)
}

public func contractSm9Pairing(g1Point: Array<Byte>, g2Point: Array<Byte>): Array<Byte> {
    try {
        sm9Pairing(
            sm9G1PointFromBytes(g1Point), sm9G2PointFromBytes(g2Point)
        ).toBytes()
    } catch (e: CryptoException) {
        throw contractSm9Exception(e, "SM9 pairing")
    }
}

public func contractSm9GenerateSignMasterKeyPair(): ContractSm9SignMasterKeyPair {
    try {
        let privateKey = sm9GenerateSignMasterPrivateKey()
        ContractSm9SignMasterKeyPair(
            privateKey.scalar.toBytesBE(paddedLen: CONTRACT_SM9_SCALAR_LEN),
            sm9G2PointToBytes(sm9SignMasterPublicKey(privateKey).point)
        )
    } catch (e: CryptoException) {
        throw contractSm9Exception(e, "SM9 signing master key generation")
    }
}

public func contractSm9SignMasterPublicFromPrivate(privateKey: Array<Byte>): Array<Byte> {
    try {
        sm9G2PointToBytes(sm9SignMasterPublicKey(contractSm9SignMasterPrivate(privateKey)).point)
    } catch (e: CryptoException) {
        throw contractSm9Exception(e, "SM9 signing master public-key derivation")
    }
}

public func contractSm9ExtractSignUserPrivateKey(
    masterPrivateKey: Array<Byte>, identity: Array<Byte>, hierarchy!: Byte = UInt8(0x01)
): ContractSm9SignUserPrivateKey {
    try {
        let user = sm9ExtractSignUserPrivateKey(
            contractSm9SignMasterPrivate(masterPrivateKey), identity, hierarchy: hierarchy
        )
        ContractSm9SignUserPrivateKey(
            sm9G1PointToBytes(user.point), sm9G2PointToBytes(user.masterPublicKey.point)
        )
    } catch (e: CryptoException) {
        throw contractSm9Exception(e, "SM9 signing user-key extraction")
    }
}

public func contractSm9Sign(
    userPrivateKey: ContractSm9SignUserPrivateKey, message: Array<Byte>
): Array<Byte> {
    try {
        sm9Sign(contractSm9SignUserPrivate(userPrivateKey), message).toBytes()
    } catch (e: CryptoException) {
        throw contractSm9Exception(e, "SM9 signing")
    }
}

public func contractSm9Verify(
    masterPublicKey: Array<Byte>,
    identity: Array<Byte>,
    message: Array<Byte>,
    signature: Array<Byte>,
    hierarchy!: Byte = UInt8(0x01)
): Bool {
    try {
        sm9Verify(
            Sm9SignMasterPublicKey(sm9G2PointFromBytes(masterPublicKey)),
            identity,
            message,
            Sm9Signature.fromBytes(signature),
            hierarchy: hierarchy
        )
    } catch (e: CryptoException) {
        throw contractSm9Exception(e, "SM9 verification")
    }
}

public func contractSm9GenerateEncryptionMasterKeyPair(): ContractSm9EncryptionMasterKeyPair {
    try {
        let privateKey = sm9GenerateEncryptionMasterPrivateKey()
        ContractSm9EncryptionMasterKeyPair(
            privateKey.scalar.toBytesBE(paddedLen: CONTRACT_SM9_SCALAR_LEN),
            sm9G1PointToBytes(sm9EncryptionMasterPublicKey(privateKey).point)
        )
    } catch (e: CryptoException) {
        throw contractSm9Exception(e, "SM9 encryption master key generation")
    }
}

public func contractSm9EncryptionMasterPublicFromPrivate(privateKey: Array<Byte>): Array<Byte> {
    try {
        sm9G1PointToBytes(
            sm9EncryptionMasterPublicKey(contractSm9EncryptionMasterPrivate(privateKey)).point
        )
    } catch (e: CryptoException) {
        throw contractSm9Exception(e, "SM9 encryption master public-key derivation")
    }
}

public func contractSm9ExtractEncryptionUserPrivateKey(
    masterPrivateKey: Array<Byte>, identity: Array<Byte>, hierarchy!: Byte = UInt8(0x03)
): ContractSm9EncryptionUserPrivateKey {
    try {
        let user = sm9ExtractEncryptionUserPrivateKey(
            contractSm9EncryptionMasterPrivate(masterPrivateKey), identity, hierarchy: hierarchy
        )
        ContractSm9EncryptionUserPrivateKey(
            sm9G2PointToBytes(user.point), sm9G1PointToBytes(user.masterPublicKey.point)
        )
    } catch (e: CryptoException) {
        throw contractSm9Exception(e, "SM9 encryption user-key extraction")
    }
}

public func contractSm9Encrypt(
    masterPublicKey: Array<Byte>,
    identity: Array<Byte>,
    plaintext: Array<Byte>,
    hierarchy!: Byte = UInt8(0x03)
): Array<Byte> {
    try {
        sm9Encrypt(
            Sm9EncryptionMasterPublicKey(sm9G1PointFromBytes(masterPublicKey)),
            identity,
            plaintext,
            hierarchy: hierarchy
        )
    } catch (e: CryptoException) {
        throw contractSm9Exception(e, "SM9 encryption")
    }
}

public func contractSm9Decrypt(
    userPrivateKey: ContractSm9EncryptionUserPrivateKey,
    identity: Array<Byte>,
    ciphertext: Array<Byte>
): Array<Byte> {
    try {
        sm9Decrypt(contractSm9EncryptionUserPrivate(userPrivateKey), identity, ciphertext)
    } catch (e: CryptoException) {
        throw contractSm9Exception(e, "SM9 decryption")
    }
}

public func contractSm9BeginKeyExchange(
    userPrivateKey: ContractSm9EncryptionUserPrivateKey,
    selfIdentity: Array<Byte>,
    peerIdentity: Array<Byte>,
    hierarchy!: Byte = UInt8(0x02)
): ContractSm9KeyExchangeState {
    try {
        ContractSm9KeyExchangeState(sm9BeginKeyExchange(
            contractSm9EncryptionUserPrivate(userPrivateKey),
            selfIdentity,
            peerIdentity,
            hierarchy: hierarchy
        ))
    } catch (e: CryptoException) {
        throw contractSm9Exception(e, "SM9 key-exchange initialization")
    }
}

public func contractSm9CompleteKeyExchange(
    state: ContractSm9KeyExchangeState,
    peerEphemeralPublicKey: Array<Byte>,
    initiator: Bool,
    keyLen: Int64
): ContractSm9KeyExchangeResult {
    try {
        state.complete(peerEphemeralPublicKey, initiator, keyLen)
    } catch (e: CryptoException) {
        throw contractSm9Exception(e, "SM9 key-exchange completion")
    }
}

public func contractSm9VerifyKeyExchangeConfirmation(
    expected: Array<Byte>, received: Array<Byte>
): Bool {
    sm9VerifyKeyExchangeConfirmation(expected, received)
}

private func contractSm9SignMasterPrivate(encoded: Array<Byte>): Sm9SignMasterPrivateKey {
    contractSm9RequireSize(encoded, CONTRACT_SM9_SCALAR_LEN, "SM9 signing master private key")
    Sm9SignMasterPrivateKey(BigNum.fromBytesBE(encoded))
}

private func contractSm9EncryptionMasterPrivate(
    encoded: Array<Byte>
): Sm9EncryptionMasterPrivateKey {
    contractSm9RequireSize(encoded, CONTRACT_SM9_SCALAR_LEN, "SM9 encryption master private key")
    Sm9EncryptionMasterPrivateKey(BigNum.fromBytesBE(encoded))
}

private func contractSm9SignUserPrivate(
    value: ContractSm9SignUserPrivateKey
): Sm9SignUserPrivateKey {
    Sm9SignUserPrivateKey(
        sm9G1PointFromBytes(value.privateKey),
        Sm9SignMasterPublicKey(sm9G2PointFromBytes(value.masterPublicKey))
    )
}

private func contractSm9EncryptionUserPrivate(
    value: ContractSm9EncryptionUserPrivateKey
): Sm9EncryptionUserPrivateKey {
    Sm9EncryptionUserPrivateKey(
        sm9G2PointFromBytes(value.privateKey),
        Sm9EncryptionMasterPublicKey(sm9G1PointFromBytes(value.masterPublicKey))
    )
}

private func contractSm9RequireSize(value: Array<Byte>, expected: Int64, label: String): Unit {
    if (value.size != expected) {
        throw ContractException(
            ContractErrorCode.BadInput, "${label} must be ${expected} bytes"
        )
    }
}

private func contractSm9Exception(error: CryptoException, operation: String): ContractException {
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
