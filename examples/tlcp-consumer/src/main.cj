package jinguissl_tlcp_consumer

import std.console.Console
import std.convert.*
import std.fs.File
import jinguissl.contract.*

func readText(path: String): String { String.fromUtf8(File.readFrom(path)) }
func hex(bytes: Array<Byte>): String {
    let digits = "0123456789abcdef".toArray()
    let text = Array<Byte>(bytes.size * 2, repeat: 0)
    for (i in 0..bytes.size) { text[i * 2] = digits[Int64(bytes[i] >> 4)]; text[i * 2 + 1] = digits[Int64(bytes[i] & 15)] }
    String.fromUtf8(text)
}
func unhex(text: String): Array<Byte> {
    let raw = text.toArray()
    if (raw.size % 2 != 0) { throw Exception("odd hex input") }
    let bytes = Array<Byte>(raw.size / 2, repeat: 0)
    for (i in 0..raw.size) {
        let b = raw[i]
        let n = if (b >= 48 && b <= 57) { b - 48 } else if (b >= 97 && b <= 102) { b - 87 }
            else { throw Exception("invalid hex input") }
        bytes[i / 2] = (bytes[i / 2] << 4) | n
    }
    bytes
}

// Same line protocol as the Core test adapter, with only a direct Contract dependency.
main(args: Array<String>): Int64 {
    if (args.size != 4) { println("usage: client|server decimal-suite fixture-folder validation-time"); return 2 }
    let role = if (args[0] == "client") { ContractTlcpRole.Client } else { ContractTlcpRole.Server }
    var selected = ContractTlcpCipherSuite.EccSm4GcmSm3
    var found = false
    for (suite in contractTlcpDefaultCipherSuites()) {
        if (suite.wireValue() == Int64.parse(args[1])) { selected = suite; found = true }
    }
    if (!found) { throw Exception("unsupported test suite") }
    let prefix = args[2] + "/" + args[0]
    let signKey = contractGmParseSm2PrivateKeyPkcs8Pem(readText(prefix + "-sign.key"))
    let encKey = contractGmParseSm2PrivateKeyPkcs8Pem(readText(prefix + "-enc.key"))
    let identity = ContractTlcpIdentity(signKey, encKey,
        contractGmParseCertificatePem(readText(prefix + "-sign.pem")).der,
        contractGmParseCertificatePem(readText(prefix + "-enc.pem")).der)
    for (bytes in [signKey, encKey]) { for (i in 0..bytes.size) { bytes[i] = 0 } }
    let session = ContractTlcpSession(role, readText(args[2] + "/root.pem"), args[3],
        expectedPeerDnsName: if (args[0] == "client") { "localhost" } else { "" }, identity: Some(identity),
        policy: ContractTlcpProviderPolicy(cipherSuites: [selected], requireClientCertificate: true))
    identity.destroy()
    try {
        session.start(0)
        while (true) {
            for (wire in session.takeOutput()) { println("OUT " + hex(wire)) }
            println("READY " + session.handshakeComplete.toString())
            Console.stdOut.flush()
            let line = match (Console.stdIn.readln()) { case Some(value) => value; case None => break }
            let parts = line.split(' ')
            if (parts[0] == "QUIT") { break }
            if (parts[0] == "RX") {
                for (plain in session.receive(unhex(parts[2]), Int64.parse(parts[1]))) { println("DATA " + hex(plain)) }
            } else if (parts[0] == "TICK") { session.onTimeout(Int64.parse(parts[1])) }
            else if (parts[0] == "APP") { println("OUT " + hex(session.sealApplicationData(unhex(parts[1])))) }
            else if (parts[0] == "CLOSE") { session.closeNotify() }
        }
    } catch (e: ContractTlcpProviderRefusal) { println("FAIL " + e.reason + " " + e.message); return 1 }
      finally { session.close() }
    0
}
