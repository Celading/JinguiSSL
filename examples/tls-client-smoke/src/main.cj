package jinguissl_tls_client_smoke

import std.fs.File
import std.convert.*
import std.net.TcpSocket
import jinguissl.contract.*

main(args: Array<String>): Int64 {
    if (args.size != 2) { println("usage: <port> <cipher-suite-decimal>"); return 2 }
    let client = ContractTls13StreamClient(
        String.fromUtf8(File.readFrom("../../testdata/x509/engine_root.pem")),
        "www.example.com", "270101000000Z", alpnProtocols: ["mqtt"], requireAlpn: true,
        cipherSuites: [Int64.parse(args[1])]
    )
    let socket = TcpSocket("127.0.0.1", UInt16.parse(args[0]))
    socket.connect()
    socket.readTimeout = Duration.second * 5
    try {
        socket.write(client.takeHandshakeOutput())
        let buffer = Array<Byte>(37, repeat: 0)
        var loops: Int64 = 0
        while (!client.authenticated) {
            loops += 1
            if (loops > 8192) { throw Exception("handshake read budget exceeded") }
            let count = socket.read(buffer)
            if (count == 0) { throw Exception("unexpected EOF during handshake") }
            _ = client.receive(buffer[..count])
            let output = client.takeHandshakeOutput()
            if (output.size > 0) { socket.write(output) }
        }
        if (client.selectedAlpn() != "mqtt") { throw Exception("non-HTTP ALPN was lost") }
        socket.write(client.sealApplicationData("ping".toArray()))
        var response = ""
        while (response.size < 4) {
            let count = socket.read(buffer)
            if (count == 0) { throw Exception("unexpected EOF before response") }
            for (data in client.receive(buffer[..count])) { response = "${response}${String.fromUtf8(data)}" }
        }
        if (response != "pong") { throw Exception("application-data mismatch") }
        socket.write(client.closeNotify())
        println("TLS client: authenticated mqtt ALPN, server/client Finished, bidirectional application data OK")
    } finally {
        client.close()
        socket.close()
    }
    0
}
