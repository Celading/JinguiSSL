package jinguissl_quic_crypto_smoke

import std.convert.*
import std.fs.File
import std.net.TcpSocket
import jinguissl.contract.*

// Length-prefixed loopback test carrier only, NOT QUIC packet/CRYPTO framing.
func writeFrame(socket: TcpSocket, bytes: Array<Byte>): Unit {
    let n = bytes.size
    socket.write([UInt8((n >> 24) & 255), UInt8((n >> 16) & 255), UInt8((n >> 8) & 255), UInt8(n & 255)])
    socket.write(bytes)
}
func readExact(socket: TcpSocket, size: Int64): Array<Byte> {
    let bytes = Array<Byte>(size, repeat: 0)
    var offset: Int64 = 0
    while (offset < size) {
        let count = socket.read(bytes[offset..])
        if (count == 0) { throw Exception("unexpected test-carrier EOF") }
        offset += count
    }
    bytes
}
func readFrame(socket: TcpSocket): Array<Byte> {
    let header = readExact(socket, 4)
    let n = (Int64(header[0]) << 24) | (Int64(header[1]) << 16) | (Int64(header[2]) << 8) | Int64(header[3])
    if (n > 262144) { throw Exception("test carrier exceeds budget") }
    readExact(socket, n)
}

func protectionSmoke(): Unit {
    let id: Array<Byte> = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
    let (key, iv, hp) = contractQuicInitialKeyDerive(id, false)
    if (contractBytesToHexLower(key) != "1f369613dd76d5467730efcbe3b1a22d" ||
        contractBytesToHexLower(iv) != "fa044b2f42a3fd3b46fb255c" ||
        contractBytesToHexLower(hp) != "9f50449e04a0e810283a1e9933adedd2") {
        throw Exception("RFC 9001 Initial vector mismatch")
    }
    let algorithm = ContractQuicAeadAlgorithm.Aes128Gcm
    let plaintext = "quic payload".toArray()
    let sealed = contractQuicAeadEncrypt(key, iv, 7, plaintext, id, algorithm)
    if (contractQuicAeadDecrypt(key, iv, 7, sealed, id, algorithm) != plaintext) {
        throw Exception("QUIC AEAD roundtrip mismatch")
    }
    let (_, mask) = contractQuicHpAesEncrypt(sealed[..16], hp)
    if (mask.size < 4) { throw Exception("QUIC HP mask too short") }
    sealed[sealed.size - 1] ^= UInt8(1)
    var rejected = false
    try { _ = contractQuicAeadDecrypt(key, iv, 7, sealed, id, algorithm) } catch (_: ContractException) { rejected = true }
    if (!rejected) { throw Exception("QUIC AEAD accepted tampering") }
    let retry: Array<Byte> = [0xff, 0, 0, 0, 1, 0, 8, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e]
    if (contractBytesToHexLower(contractQuicRetryIntegrityTag(retry, id, false)) != "04a265ba2eff4d829058fb3f0f2496ba") {
        throw Exception("RFC 9001 Retry vector mismatch")
    }
    println("QUIC protection: Initial/HP/AEAD/Retry and tamper rejection OK")
}

main(args: Array<String>): Int64 {
    protectionSmoke()
    if (args.size == 0) { return 0 }
    if (args.size != 2) { return 2 }
    let client = ContractTls13ClientEngine(
        String.fromUtf8(File.readFrom("../../testdata/x509/engine_root.pem")),
        "www.example.com", "270101000000Z", alpnProtocols: ["igquic-echo"],
        cipherSuites: [Int64.parse(args[1])], quicTransportParameters: Some([UInt8(1), UInt8(0)])
    )
    let socket = TcpSocket("127.0.0.1", UInt16.parse(args[0]))
    socket.connect()
    socket.readTimeout = Duration.second * 5
    try {
        writeFrame(socket, client.clientHello())
        for (b in readFrame(socket)) { client.receiveInitial([b]) }
        let hs = client.handshakeSecrets()
        let flight = readFrame(socket)
        var offset: Int64 = 0
        while (offset < flight.size) {
            let end = if (offset + 7 < flight.size) { offset + 7 } else { flight.size }
            client.receiveHandshake(flight[offset..end])
            offset = end
        }
        if (!client.authenticated || client.selectedAlpn() != "igquic-echo" ||
            client.peerTransportParameters() != [UInt8(3), UInt8(0)]) { throw Exception("QUIC auth result mismatch") }
        let app = client.applicationSecrets()
        writeFrame(socket, client.clientFinished())
        writeFrame(socket, contractSha256(hs.clientTrafficSecret()))
        writeFrame(socket, contractSha256(hs.serverTrafficSecret()))
        writeFrame(socket, contractSha256(app.clientTrafficSecret()))
        writeFrame(socket, contractSha256(app.serverTrafficSecret()))
        hs.destroy()
        app.destroy()
        if (readFrame(socket) != [UInt8(1)]) { throw Exception("external peer rejected Finished or phase keys") }
        println("QUIC raw handshake: independent peer verified client Finished and all four phase/direction secrets")
    } finally {
        client.close()
        socket.close()
    }
    0
}
