package jinguissl.contract

import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.kem.{
    rsaKemEncapsulate,
    rsaKemDecapsulate,
    ecdhKemEncapsulate,
    ecdhKemDecapsulate
}

public class ContractKemEncapsulation {
    public let encapsulatedKey: Array<Byte>
    public let sharedSecret: Array<Byte>

    public init(encapsulatedKey: Array<Byte>, sharedSecret: Array<Byte>) {
        if (encapsulatedKey.size == 0 || sharedSecret.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "KEM result must not be empty")
        }
        this.encapsulatedKey = encapsulatedKey.clone()
        this.sharedSecret = sharedSecret.clone()
    }
}

public func contractRsaKemEncapsulate(
    publicKey: ContractRsaPublicKey,
    sharedSecretLen!: Int64 = 32,
    info!: Array<Byte> = []
): ContractKemEncapsulation {
    try {
        let (encapsulated, secret) = rsaKemEncapsulate(
            contractRsaCorePublicKey(publicKey),
            sharedSecretLen: sharedSecretLen,
            info: info
        )
        ContractKemEncapsulation(encapsulated, secret)
    } catch (e: CryptoException) {
        throw contractKemException(e, "RSA-KEM encapsulation")
    }
}

public func contractRsaKemDecapsulate(
    privateKey: ContractRsaPrivateKey,
    encapsulatedKey: Array<Byte>,
    sharedSecretLen!: Int64 = 32,
    info!: Array<Byte> = []
): Array<Byte> {
    try {
        rsaKemDecapsulate(
            contractRsaCorePrivateKey(privateKey),
            encapsulatedKey,
            sharedSecretLen: sharedSecretLen,
            info: info
        )
    } catch (e: CryptoException) {
        throw contractKemException(e, "RSA-KEM decapsulation")
    }
}

public func contractEcdhKemEncapsulate(
    publicKey: ContractEcPublicKey,
    sharedSecretLen!: Int64 = 32,
    info!: Array<Byte> = []
): ContractKemEncapsulation {
    try {
        let (encapsulated, secret) = ecdhKemEncapsulate(
            contractEcCorePublicKey(publicKey),
            sharedSecretLen: sharedSecretLen,
            info: info
        )
        ContractKemEncapsulation(encapsulated, secret)
    } catch (e: CryptoException) {
        throw contractKemException(e, "ECDH-KEM encapsulation")
    }
}

public func contractEcdhKemDecapsulate(
    curve: ContractEcCurve,
    privateKey: Array<Byte>,
    encapsulatedKey: Array<Byte>,
    sharedSecretLen!: Int64 = 32,
    info!: Array<Byte> = []
): Array<Byte> {
    try {
        ecdhKemDecapsulate(
            contractEcPrivateKey(curve, privateKey),
            encapsulatedKey,
            sharedSecretLen: sharedSecretLen,
            info: info
        )
    } catch (e: CryptoException) {
        throw contractKemException(e, "ECDH-KEM decapsulation")
    }
}

private func contractKemException(exception: CryptoException, operation: String): ContractException {
    ContractException(
        contractMapCoreCryptoException(exception),
        "${operation} failed: ${exception.message}"
    )
}
