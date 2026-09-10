package jinguissl_webauthn_crypto_smoke
import std.fs.File
import jinguissl.contract.*

main(): Int64 {
    let prefix = "../../testdata/x509/engine_webauthn_"
    let message = File.readFrom("${prefix}message.txt")
    let signature = File.readFrom("${prefix}signature.der")
    let publicKey = ContractEcPublicKey(ContractEcCurve.P256, File.readFrom("${prefix}public.bin"))
    if (!contractEs256VerifyDer(publicKey, message, signature)) { throw Exception("OpenSSL ES256 fixture rejected") }
    if (contractSha256(message).size != 32) { throw Exception("SHA-256 shape mismatch") }
    message[0] ^= UInt8(1)
    if (contractEs256VerifyDer(publicKey, message, signature)) { throw Exception("tampered signed bytes accepted") }
    println("WebAuthn crypto supply: independent ES256 DER signature and SHA-256 OK; ceremony remains consumer-owned")
    0
}
