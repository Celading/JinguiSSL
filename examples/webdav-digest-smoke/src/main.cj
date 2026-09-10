package jinguissl_webdav_digest_smoke
import jinguissl.contract.*

main(): Int64 {
    let legacy = contractBytesToHexLower(contractMd5("Mufasa:testrealm@host.com:Circle Of Life".toArray()))
    if (legacy != "939e7578ed9e3c518a452acee763bce9") { throw Exception("legacy Digest MD5 vector mismatch") }
    let digest = contractBytesToHexLower(contractSha256("abc".toArray()))
    if (digest != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") {
        throw Exception("SHA-256 vector mismatch")
    }
    println("WebDAV digest supply: MD5 legacy vector, SHA-256 and hex OK; nonce/replay/auth policy remains consumer-owned")
    0
}
