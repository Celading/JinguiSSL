package jinguissl.contract

import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.ecc.ecPublicFromPrivateKey
import jinguissl_core.crypto.x509.{
    X509Certificate,
    x509ParseDer,
    x509ParsePem,
    x509FindExtension,
    x509DecodeKeyUsageFromExtension,
    x509DecodeBasicConstraintsFromExtension,
    x509ExtractExtendedKeyUsageOids,
    x509ExtractSubjectAlternativeDnsNames,
    x509ExtractCertificatePolicyOids,
    x509ExtractRsaPublicKey,
    x509ExtractEcPublicKey,
    x509ParseRsaPrivateKeyPkcs1Pem,
    x509ParseRsaPrivateKeyPkcs8Pem,
    x509ParseEcPrivateKeyPkcs8Pem,
    X509_OID_KEY_USAGE,
    X509_OID_BASIC_CONSTRAINTS
}

public class ContractX509CertificateSummary {
    public let der: Array<Byte>
    public let pem: String
    public let serialHexLower: String
    public let subjectCommonName: String
    public let issuerCommonName: String
    public let notBefore: String
    public let notAfter: String
    public let signatureAlgorithmOid: String
    public let subjectAlternativeDnsNames: Array<String>
    public let extendedKeyUsageOids: Array<String>
    public let certificatePolicyOids: Array<String>
    public let keyUsageMask: Int64
    public let certificateAuthority: Bool
    public let pathLenConstraint: ?Int64
    public let selfIssued: Bool

    public init(
        der: Array<Byte>,
        pem: String,
        serialHexLower: String,
        subjectCommonName: String,
        issuerCommonName: String,
        notBefore: String,
        notAfter: String,
        signatureAlgorithmOid: String,
        subjectAlternativeDnsNames: Array<String>,
        extendedKeyUsageOids: Array<String>,
        certificatePolicyOids: Array<String>,
        keyUsageMask: Int64,
        certificateAuthority: Bool,
        pathLenConstraint: ?Int64,
        selfIssued: Bool
    ) {
        if (der.size == 0 || pem.trimAscii().size == 0 || serialHexLower.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "X.509 summary material must not be empty")
        }
        this.der = der.clone()
        this.pem = pem
        this.serialHexLower = serialHexLower
        this.subjectCommonName = subjectCommonName
        this.issuerCommonName = issuerCommonName
        this.notBefore = notBefore
        this.notAfter = notAfter
        this.signatureAlgorithmOid = signatureAlgorithmOid
        this.subjectAlternativeDnsNames = subjectAlternativeDnsNames.clone()
        this.extendedKeyUsageOids = extendedKeyUsageOids.clone()
        this.certificatePolicyOids = certificatePolicyOids.clone()
        this.keyUsageMask = keyUsageMask
        this.certificateAuthority = certificateAuthority
        this.pathLenConstraint = pathLenConstraint
        this.selfIssued = selfIssued
    }
}

public func contractX509ParseCertificatePem(pem: String): ContractX509CertificateSummary {
    try {
        contractX509Summary(x509ParsePem(pem))
    } catch (e: CryptoException) {
        throw contractX509GeneralException(e, "X.509 PEM parsing")
    }
}

public func contractX509ParseCertificateDer(der: Array<Byte>): ContractX509CertificateSummary {
    try {
        contractX509Summary(x509ParseDer(der))
    } catch (e: CryptoException) {
        throw contractX509GeneralException(e, "X.509 DER parsing")
    }
}

public func contractX509ExtractRsaPublicKeyPem(pem: String): ContractRsaPublicKey {
    try {
        let key = x509ExtractRsaPublicKey(x509ParsePem(pem))
        ContractRsaPublicKey(key.modulus.toBytesBE(), key.exponent.toBytesBE())
    } catch (e: CryptoException) {
        throw contractX509GeneralException(e, "X.509 RSA public-key extraction")
    }
}

public func contractX509ExtractEcPublicKeyPem(pem: String): ContractEcPublicKey {
    try {
        contractEcPublicKey(x509ExtractEcPublicKey(x509ParsePem(pem)))
    } catch (e: CryptoException) {
        throw contractX509GeneralException(e, "X.509 EC public-key extraction")
    }
}

public func contractX509ParseRsaPrivateKeyPkcs1Pem(pem: String): ContractRsaPrivateKey {
    try {
        contractRsaPrivateKey(x509ParseRsaPrivateKeyPkcs1Pem(pem))
    } catch (e: CryptoException) {
        throw contractX509GeneralException(e, "RSA PKCS#1 private-key parsing")
    }
}

public func contractX509ParseRsaPrivateKeyPkcs8Pem(pem: String): ContractRsaPrivateKey {
    try {
        contractRsaPrivateKey(x509ParseRsaPrivateKeyPkcs8Pem(pem))
    } catch (e: CryptoException) {
        throw contractX509GeneralException(e, "RSA PKCS#8 private-key parsing")
    }
}

public func contractX509ParseEcPrivateKeyPkcs8Pem(pem: String): ContractEcKeyPair {
    try {
        let privateKey = x509ParseEcPrivateKeyPkcs8Pem(pem)
        let publicKey = contractEcPublicKey(ecPublicFromPrivateKey(privateKey))
        let curve = publicKey.curve
        ContractEcKeyPair(
            curve,
            privateKey.scalar.toBytesBE(paddedLen: curve.fieldLen()),
            publicKey
        )
    } catch (e: CryptoException) {
        throw contractX509GeneralException(e, "EC PKCS#8 private-key parsing")
    }
}

private func contractX509Summary(cert: X509Certificate): ContractX509CertificateSummary {
    var keyUsageMask: Int64 = 0
    match (x509FindExtension(cert, X509_OID_KEY_USAGE)) {
        case Some(extension) => keyUsageMask = x509DecodeKeyUsageFromExtension(extension)
        case None => ()
    }
    var certificateAuthority: Bool = false
    var pathLenConstraint: ?Int64 = None
    match (x509FindExtension(cert, X509_OID_BASIC_CONSTRAINTS)) {
        case Some(extension) =>
            let constraints = x509DecodeBasicConstraintsFromExtension(extension)
            certificateAuthority = constraints.ca
            pathLenConstraint = constraints.pathLenConstraint
        case None => ()
    }
    ContractX509CertificateSummary(
        cert.der,
        cert.toPem(),
        cert.serialHexLower(),
        cert.subject.commonName(),
        cert.issuer.commonName(),
        cert.notBefore,
        cert.notAfter,
        cert.signatureAlgorithmOid,
        x509ExtractSubjectAlternativeDnsNames(cert),
        x509ExtractExtendedKeyUsageOids(cert),
        x509ExtractCertificatePolicyOids(cert),
        keyUsageMask,
        certificateAuthority,
        pathLenConstraint,
        cert.isSelfIssued()
    )
}

private func contractX509GeneralException(
    exception: CryptoException, operation: String
): ContractException {
    ContractException(
        contractMapCoreCryptoException(exception),
        "${operation} failed: ${exception.message}"
    )
}
