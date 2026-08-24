package jinguissl.contract

import std.collection.ArrayList
import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.error.{CryptoErrorCode, CryptoException}
import jinguissl_core.crypto.sm2.{Sm2PrivateKey, sm2PublicKey, sm2PublicKeyFromUncompressed, sm2PublicKeyToUncompressed}
import jinguissl_core.crypto.x509.*

public let CONTRACT_GM_DEFAULT_SIGNER_IDENTITY: String = "1234567812345678"
public let CONTRACT_GM_KEY_USAGE_DIGITAL_SIGNATURE: Int64 = Int64(1) << 0
public let CONTRACT_GM_KEY_USAGE_CONTENT_COMMITMENT: Int64 = Int64(1) << 1
public let CONTRACT_GM_KEY_USAGE_KEY_ENCIPHERMENT: Int64 = Int64(1) << 2
public let CONTRACT_GM_KEY_USAGE_DATA_ENCIPHERMENT: Int64 = Int64(1) << 3
public let CONTRACT_GM_KEY_USAGE_KEY_AGREEMENT: Int64 = Int64(1) << 4
public let CONTRACT_GM_KEY_USAGE_KEY_CERT_SIGN: Int64 = Int64(1) << 5
public let CONTRACT_GM_KEY_USAGE_CRL_SIGN: Int64 = Int64(1) << 6

public class ContractGmSm2KeyContainers {
    public let keyPair: ContractSm2KeyPair
    public let publicKeyDer: Array<Byte>
    public let publicKeyPem: String
    public let sec1Der: Array<Byte>
    public let sec1Pem: String
    public let pkcs8Der: Array<Byte>
    public let pkcs8Pem: String

    public init(
        keyPair: ContractSm2KeyPair,
        publicKeyDer: Array<Byte>,
        publicKeyPem: String,
        sec1Der: Array<Byte>,
        sec1Pem: String,
        pkcs8Der: Array<Byte>,
        pkcs8Pem: String
    ) {
        if (
            publicKeyDer.size == 0 || sec1Der.size == 0 || pkcs8Der.size == 0 ||
            publicKeyPem.trimAscii().size == 0 || sec1Pem.trimAscii().size == 0 ||
            pkcs8Pem.trimAscii().size == 0
        ) {
            throw ContractException(ContractErrorCode.BadInput, "SM2 key containers must not be empty")
        }
        this.keyPair = keyPair
        this.publicKeyDer = publicKeyDer.clone()
        this.publicKeyPem = publicKeyPem
        this.sec1Der = sec1Der.clone()
        this.sec1Pem = sec1Pem
        this.pkcs8Der = pkcs8Der.clone()
        this.pkcs8Pem = pkcs8Pem
    }
}

public class ContractGmCertificateRequest {
    public let der: Array<Byte>
    public let pem: String
    public let commonName: String
    public let publicKey: Array<Byte>

    public init(der: Array<Byte>, pem: String, commonName: String, publicKey: Array<Byte>) {
        if (der.size == 0 || pem.trimAscii().size == 0 || commonName.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "SM2 CSR fields must not be empty")
        }
        if (publicKey.size != CONTRACT_SM2_PUBLIC_KEY_LEN) {
            throw ContractException(ContractErrorCode.BadInput, "SM2 CSR public key must be 65 bytes")
        }
        this.der = der.clone()
        this.pem = pem
        this.commonName = commonName
        this.publicKey = publicKey.clone()
    }
}

public class ContractGmCertificateConfig {
    public let commonName: String
    public let serialNumber: Array<Byte>
    public let notBefore: String
    public let notAfter: String
    public let keyUsageMask: Int64

    public init(
        commonName: String,
        serialNumber!: Array<Byte> = [UInt8(1)],
        notBefore!: String = "260101000000Z",
        notAfter!: String = "360101000000Z",
        keyUsageMask!: Int64 = CONTRACT_GM_KEY_USAGE_DIGITAL_SIGNATURE
    ) {
        if (commonName.trimAscii().size == 0 || serialNumber.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "GM certificate name and serial must not be empty")
        }
        if (notBefore.trimAscii().size == 0 || notAfter.trimAscii().size == 0 || keyUsageMask < 0) {
            throw ContractException(ContractErrorCode.BadInput, "GM certificate validity or key usage is invalid")
        }
        this.commonName = commonName.trimAscii()
        this.serialNumber = serialNumber.clone()
        this.notBefore = notBefore
        this.notAfter = notAfter
        this.keyUsageMask = keyUsageMask
    }
}

public class ContractGmCertificate {
    public let der: Array<Byte>
    public let pem: String
    public let serialNumber: Array<Byte>
    public let subjectCommonName: String
    public let issuerCommonName: String
    public let notBefore: String
    public let notAfter: String
    public let publicKey: Array<Byte>
    public let selfIssued: Bool

    public init(
        der: Array<Byte>,
        pem: String,
        serialNumber: Array<Byte>,
        subjectCommonName: String,
        issuerCommonName: String,
        notBefore: String,
        notAfter: String,
        publicKey: Array<Byte>,
        selfIssued: Bool
    ) {
        if (der.size == 0 || pem.trimAscii().size == 0 || serialNumber.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "GM certificate material must not be empty")
        }
        this.der = der.clone()
        this.pem = pem
        this.serialNumber = serialNumber.clone()
        this.subjectCommonName = subjectCommonName
        this.issuerCommonName = issuerCommonName
        this.notBefore = notBefore
        this.notAfter = notAfter
        this.publicKey = publicKey.clone()
        this.selfIssued = selfIssued
    }
}

public class ContractGmCertificateChainResult {
    public let chainPem: Array<String>
    public let trustAnchorPem: String

    public init(chainPem: Array<String>, trustAnchorPem: String) {
        if (chainPem.size == 0 || trustAnchorPem.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "verified GM chain must not be empty")
        }
        this.chainPem = chainPem.clone()
        this.trustAnchorPem = trustAnchorPem
    }
}

public class ContractGmRevokedCertificate {
    public let serialNumber: Array<Byte>
    public let revocationTime: String

    public init(serialNumber: Array<Byte>, revocationTime: String) {
        if (serialNumber.size == 0 || revocationTime.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "revoked serial and time must not be empty")
        }
        this.serialNumber = serialNumber.clone()
        this.revocationTime = revocationTime
    }
}

public class ContractGmCrl {
    public let der: Array<Byte>
    public let pem: String
    public let thisUpdate: String
    public let nextUpdate: String
    public let revokedSerialHexLower: Array<String>

    public init(
        der: Array<Byte>, pem: String, thisUpdate: String, nextUpdate: String,
        revokedSerialHexLower: Array<String>
    ) {
        if (der.size == 0 || pem.trimAscii().size == 0 || thisUpdate.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "GM CRL material must not be empty")
        }
        this.der = der.clone()
        this.pem = pem
        this.thisUpdate = thisUpdate
        this.nextUpdate = nextUpdate
        this.revokedSerialHexLower = revokedSerialHexLower.clone()
    }
}

public func contractGmSm2KeyContainers(privateKey: Array<Byte>): ContractGmSm2KeyContainers {
    try {
        let corePrivate = contractGmX509PrivateKey(privateKey)
        let corePublic = sm2PublicKey(corePrivate)
        ContractGmSm2KeyContainers(
            ContractSm2KeyPair(privateKey, sm2PublicKeyToUncompressed(corePublic)),
            x509EncodeSm2PublicKeyDer(corePublic),
            x509EncodeSm2PublicKeyPem(corePublic),
            x509EncodeSm2PrivateKeySec1Der(corePrivate),
            x509EncodeSm2PrivateKeySec1Pem(corePrivate),
            x509EncodeSm2PrivateKeyPkcs8Der(corePrivate),
            x509EncodeSm2PrivateKeyPkcs8Pem(corePrivate)
        )
    } catch (e: CryptoException) {
        throw contractGmX509Exception(e, "SM2 key-container encoding")
    }
}

public func contractGmParseSm2PublicKeyPem(pem: String): Array<Byte> {
    try {
        sm2PublicKeyToUncompressed(x509ParseSm2PublicKeyPem(pem))
    } catch (e: CryptoException) {
        throw contractGmX509Exception(e, "SM2 public-key PEM parsing")
    }
}

public func contractGmParseSm2PrivateKeySec1Pem(pem: String): Array<Byte> {
    try {
        x509ParseSm2PrivateKeySec1Pem(pem).scalar.toBytesBE(paddedLen: 32)
    } catch (e: CryptoException) {
        throw contractGmX509Exception(e, "SM2 SEC1 private-key parsing")
    }
}

public func contractGmParseSm2PrivateKeyPkcs8Pem(pem: String): Array<Byte> {
    try {
        x509ParseSm2PrivateKeyPkcs8Pem(pem).scalar.toBytesBE(paddedLen: 32)
    } catch (e: CryptoException) {
        throw contractGmX509Exception(e, "SM2 PKCS8 private-key parsing")
    }
}

public func contractGmCreateCertificateRequest(
    commonName: String,
    privateKey: Array<Byte>,
    signerIdentity!: Array<Byte> = CONTRACT_GM_DEFAULT_SIGNER_IDENTITY.toArray()
): ContractGmCertificateRequest {
    try {
        contractGmX509Request(
            x509CreateSm2CertificateRequest(
                commonName, contractGmX509PrivateKey(privateKey), signerIdentity: signerIdentity
            ),
            signerIdentity
        )
    } catch (e: CryptoException) {
        throw contractGmX509Exception(e, "SM2 certificate-request creation")
    }
}

public func contractGmParseAndVerifyCertificateRequestPem(
    pem: String,
    signerIdentity!: Array<Byte> = CONTRACT_GM_DEFAULT_SIGNER_IDENTITY.toArray()
): ContractGmCertificateRequest {
    try {
        contractGmX509Request(x509ParseSm2CertificateRequestPem(pem), signerIdentity)
    } catch (e: CryptoException) {
        throw contractGmX509Exception(e, "SM2 certificate-request verification")
    }
}

public func contractGmCreateSelfSignedCertificate(
    config: ContractGmCertificateConfig,
    privateKey: Array<Byte>,
    signerIdentity!: Array<Byte> = CONTRACT_GM_DEFAULT_SIGNER_IDENTITY.toArray()
): ContractGmCertificate {
    try {
        contractGmX509Certificate(x509CreateSelfSignedSm2Certificate(
            X509SelfSignedConfig(
                config.commonName,
                serialNumber: config.serialNumber,
                notBefore: config.notBefore,
                notAfter: config.notAfter,
                keyUsageMask: config.keyUsageMask
            ),
            contractGmX509PrivateKey(privateKey),
            signerIdentity: signerIdentity
        ))
    } catch (e: CryptoException) {
        throw contractGmX509Exception(e, "self-signed SM2 certificate creation")
    }
}

public func contractGmIssueCertificate(
    config: ContractGmCertificateConfig,
    subjectPublicKey: Array<Byte>,
    issuerCertificatePem: String,
    issuerPrivateKey: Array<Byte>,
    signerIdentity!: Array<Byte> = CONTRACT_GM_DEFAULT_SIGNER_IDENTITY.toArray()
): ContractGmCertificate {
    try {
        contractGmX509Certificate(x509CreateSm2Certificate(
            X509Sm2CertificateConfig(
                config.commonName,
                serialNumber: config.serialNumber,
                notBefore: config.notBefore,
                notAfter: config.notAfter,
                keyUsageMask: config.keyUsageMask
            ),
            sm2PublicKeyFromUncompressed(subjectPublicKey),
            x509ParsePem(issuerCertificatePem),
            contractGmX509PrivateKey(issuerPrivateKey),
            signerIdentity: signerIdentity
        ))
    } catch (e: CryptoException) {
        throw contractGmX509Exception(e, "SM2 certificate issuance")
    }
}

public func contractGmParseCertificatePem(pem: String): ContractGmCertificate {
    try {
        contractGmX509Certificate(x509ParsePem(pem))
    } catch (e: CryptoException) {
        throw contractGmX509Exception(e, "SM2 certificate parsing")
    }
}

public func contractGmVerifyCertificateChainPem(
    leafCertificatePem: String,
    trustAnchorsPem: String,
    intermediatesPem!: String = "",
    validationTime!: String = "",
    requiredLeafKeyUsageMask!: Int64 = 0,
    crlPem!: String = "",
    requireCrlForAllIssuers!: Bool = false
): ContractGmCertificateChainResult {
    try {
        let anchors = x509ParsePemChain(trustAnchorsPem)
        let intermediates: Array<X509Certificate> = if (intermediatesPem.trimAscii().size == 0) {
            []
        } else {
            x509ParsePemChain(intermediatesPem)
        }
        let crls: Array<X509Crl> = if (crlPem.trimAscii().size == 0) {
            []
        } else {
            [x509ParseCrlPem(crlPem)]
        }
        let verified = x509VerifyCertificateChain(
            x509ParsePem(leafCertificatePem),
            X509VerificationPolicy(
                anchors,
                intermediates: intermediates,
                crls: crls,
                requireCrlForAllIssuers: requireCrlForAllIssuers,
                requiredLeafKeyUsageMask: requiredLeafKeyUsageMask,
                validationTime: validationTime
            )
        )
        let chainPem = ArrayList<String>()
        for (certificate in verified.chain) { chainPem.add(certificate.toPem()) }
        ContractGmCertificateChainResult(chainPem.toArray(), verified.trustAnchor.toPem())
    } catch (e: CryptoException) {
        throw contractGmX509VerifyException(e, "SM2 certificate-chain verification")
    }
}

public func contractGmCreateCrl(
    thisUpdate: String,
    issuerCertificatePem: String,
    issuerPrivateKey: Array<Byte>,
    nextUpdate!: String = "",
    revokedCertificates!: Array<ContractGmRevokedCertificate> = [],
    signerIdentity!: Array<Byte> = CONTRACT_GM_DEFAULT_SIGNER_IDENTITY.toArray()
): ContractGmCrl {
    try {
        let revoked = ArrayList<X509Sm2RevokedCertificate>()
        for (entry in revokedCertificates) {
            revoked.add(X509Sm2RevokedCertificate(entry.serialNumber, entry.revocationTime))
        }
        let crl = x509CreateSm2Crl(
            X509Sm2CrlConfig(
                thisUpdate, nextUpdate: nextUpdate, revokedCertificates: revoked.toArray()
            ),
            x509ParsePem(issuerCertificatePem),
            contractGmX509PrivateKey(issuerPrivateKey),
            signerIdentity: signerIdentity
        )
        contractGmX509Crl(crl)
    } catch (e: CryptoException) {
        throw contractGmX509Exception(e, "SM2 CRL creation")
    }
}

public func contractGmParseAndVerifyCrlPem(
    crlPem: String,
    issuerCertificatePem: String,
    signerIdentity!: Array<Byte> = CONTRACT_GM_DEFAULT_SIGNER_IDENTITY.toArray()
): ContractGmCrl {
    try {
        let crl = x509ParseCrlPem(crlPem)
        x509VerifySm2CrlSignatureWithIssuerIdentity(
            crl, x509ParsePem(issuerCertificatePem), signerIdentity
        )
        contractGmX509Crl(crl)
    } catch (e: CryptoException) {
        throw contractGmX509VerifyException(e, "SM2 CRL verification")
    }
}

private func contractGmX509PrivateKey(encoded: Array<Byte>): Sm2PrivateKey {
    if (encoded.size != CONTRACT_SM2_PRIVATE_KEY_LEN) {
        throw ContractException(ContractErrorCode.BadInput, "SM2 private key must be 32 bytes")
    }
    Sm2PrivateKey(BigNum.fromBytesBE(encoded))
}

private func contractGmX509Request(
    request: X509Sm2CertificateRequest, signerIdentity: Array<Byte>
): ContractGmCertificateRequest {
    x509VerifySm2CertificateRequest(request, signerIdentity: signerIdentity)
    ContractGmCertificateRequest(
        request.der,
        request.toPem(),
        request.subject.commonName(),
        sm2PublicKeyToUncompressed(x509ParseSm2PublicKeyDer(request.subjectPublicKeyInfoDer))
    )
}

private func contractGmX509Certificate(certificate: X509Certificate): ContractGmCertificate {
    ContractGmCertificate(
        certificate.der,
        certificate.toPem(),
        certificate.serialNumber,
        certificate.subject.commonName(),
        certificate.issuer.commonName(),
        certificate.notBefore,
        certificate.notAfter,
        sm2PublicKeyToUncompressed(x509ExtractSm2PublicKey(certificate)),
        certificate.isSelfIssued()
    )
}

private func contractGmX509Crl(crl: X509Crl): ContractGmCrl {
    ContractGmCrl(
        crl.der, x509CrlToPem(crl), crl.thisUpdate, crl.nextUpdate,
        crl.revokedSerialHexLower
    )
}

private func contractGmX509VerifyException(
    error: CryptoException, operation: String
): ContractException {
    if (error.code == CryptoErrorCode.InvalidArgument) {
        return ContractException(ContractErrorCode.BadInput, "${operation} failed: ${error.message}")
    }
    ContractException(ContractErrorCode.VerifyFailed, "${operation} failed: ${error.message}")
}

private func contractGmX509Exception(error: CryptoException, operation: String): ContractException {
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
