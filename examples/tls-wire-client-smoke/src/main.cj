package jinguissl_tls_wire_client_smoke

import std.collection.ArrayList
import std.fs.File
import std.convert.*
import std.net.TcpSocket
import jinguissl.live.*

func readExact(socket: TcpSocket, size: Int64): Array<Byte> {
    let bytes = Array<Byte>(size, repeat: 0)
    var offset: Int64 = 0
    while (offset < size) {
        let count = socket.read(bytes[offset..])
        if (count == 0) { throw Exception("unexpected EOF") }
        offset += count
    }
    bytes
}

func readRecord(socket: TcpSocket): Array<Byte> {
    let header = readExact(socket, 5)
    let length = (Int64(header[3]) << 8) + Int64(header[4])
    if (length > 18432) { throw Exception("record length limit exceeded") }
    let out = ArrayList<Byte>(header)
    for (b in readExact(socket, length)) { out.add(b) }
    out.toArray()
}

main(args: Array<String>): Int64 {
    if (args.size != 1) { println("usage: <loopback-port>"); return 2 }
    let host = "www.example.com"
    let hello = contractTls13BuildHttpClientHelloX25519(host, alpnProtocols: ["http/1.1"])
    let trust = ContractHttpClientTlsTrustRequest(
        String.fromUtf8(File.readFrom("../../testdata/x509/engine_root.pem")), hostname: host,
        validationTime: "270101000000Z", policy: ContractTlsHttpNegotiationPolicy(
            requireServerName: true, allowedServerNames: [host], alpnPreference: ["http/1.1"]))
    let socket = TcpSocket("127.0.0.1", UInt16.parse(args[0]))
    socket.connect()
    socket.readTimeout = Duration.second * 10
    try {
        socket.write(contractTlsEncodePlaintextRecord(ContractTlsVersion.Tls12,
            ContractTlsRecordContentType.Handshake, hello.encodedClientHello))
        let wire = ArrayList<Byte>()
        var count: Int64 = 0
        while (count < 128) {
            for (b in readRecord(socket)) { wire.add(b) }
            count += 1
            let outcome = contractTryTls13OpenHttpClientRuntimeFromWireDerivedServerFlight(
                hello, trust, contractTls13CollectIncrementalHandshakeRecords([], wire.toArray()))
            if (outcome.ok) {
                let result = outcome.result ?? throw Exception("missing authenticated result")
                socket.write(result.clientFinished.encodedRecord)
                let channel = result.runtime.channelSet.clientChannel
                socket.write(channel.sealApplicationData("ping".toArray()))
                let response = channel.openApplicationData(readRecord(socket))
                if (String.fromUtf8(response) != "pong") { throw Exception("application-data mismatch") }
                println("wire client: verified peer, Finished and application data; records=" + count.toString())
                return 0
            }
            if (outcome.status != ContractTls13IncrementalHandshakeStatus.NeedMoreBytes) {
                throw Exception(outcome.status.toString() + ": " + outcome.message)
            }
        }
        throw Exception("handshake record budget exceeded")
    } finally { socket.close() }
}
