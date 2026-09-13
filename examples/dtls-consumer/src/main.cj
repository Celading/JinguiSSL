package jinguissl_dtls_consumer

import std.console.Console
import std.convert.*
import std.fs.File
import jinguissl.contract.*

func bytesToHexLower(bytes: Array<Byte>): String {
    let digits = "0123456789abcdef".toArray()
    let text = Array<Byte>(bytes.size * 2, repeat: 0)
    for (i in 0..bytes.size) { text[i * 2] = digits[Int64(bytes[i] >> 4)]; text[i * 2 + 1] = digits[Int64(bytes[i] & 15)] }
    String.fromUtf8(text)
}

func hexToBytes(text: String): Array<Byte> {
    let raw = text.toArray()
    if (raw.size % 2 != 0) { throw Exception("odd hex input") }
    let bytes = Array<Byte>(raw.size / 2, repeat: 0)
    for (i in 0..raw.size) {
        let b = raw[i]
        let n = if (b >= 48 && b <= 57) { b - 48 }
            else if (b >= 97 && b <= 102) { b - 87 }
            else { throw Exception("invalid hex input") }
        bytes[i / 2] = (bytes[i / 2] << 4) | n
    }
    bytes
}

// Line-oriented test adapter. The test runner owns UDP and monotonic time.
// Exports are ephemeral test secrets: never use this diagnostic in production.
main(args: Array<String>): Int64 {
    if (args.size != 5) { println("usage: client|server key.pem cert.der peer-sha256 profile"); return 2 }
    let identity = ContractDtlsIdentity(String.fromUtf8(File.readFrom(args[1])), File.readFrom(args[2]))
    let role = if (args[0] == "client") { ContractDtlsRole.Client } else { ContractDtlsRole.Server }
    let session = ContractDtlsSession(role, identity, args[3], [UInt8(1)], srtpProfiles: [Int64.parse(args[4])])
    identity.destroy()
    try {
        session.start(0)
        while (true) {
            for (wire in session.takeOutput()) { println("OUT " + bytesToHexLower(wire)) }
            println("READY " + session.authenticated.toString())
            Console.stdOut.flush()
            let line = match (Console.stdIn.readln()) { case Some(value) => value; case None => break }
            let parts = line.split(' ')
            if (parts[0] == "QUIT") { break }
            if (parts[0] == "RX") {
                for (plain in session.receive(hexToBytes(parts[2]), Int64.parse(parts[1]))) {
                    println("DATA " + bytesToHexLower(plain))
                }
            } else if (parts[0] == "TICK") { session.onTimeout(Int64.parse(parts[1])) }
            else if (parts[0] == "APP") { println("OUT " + bytesToHexLower(session.sealApplicationData(hexToBytes(parts[1])))) }
            else if (parts[0] == "EXPORT") {
                let keys = session.exportSrtp()
                println("KEYS " + bytesToHexLower(keys.clientWriteKey()) + bytesToHexLower(keys.serverWriteKey()) +
                    bytesToHexLower(keys.clientWriteSalt()) + bytesToHexLower(keys.serverWriteSalt()))
                keys.destroy()
            }
        }
    } finally { session.close() }
    0
}
