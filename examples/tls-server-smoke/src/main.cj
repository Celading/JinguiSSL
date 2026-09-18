package jinguissl_tls_server_smoke

import std.fs.File
import std.convert.*
import std.net.TcpSocket
import jinguissl.contract.*

main(args: Array<String>): Int64 {
    if (args.size != 2) { println("usage: <peer-port> <alpn|none>"); return 2 }
    let withAlpn = args[1] == "alpn"
    let server = ContractTls13StreamServer(
        String.fromUtf8(File.readFrom("../../testdata/x509/engine_leaf.pem")),
        String.fromUtf8(File.readFrom("../../testdata/x509/policy_leaf_key_pkcs8.pem")),
        alpnProtocols: if (withAlpn) { ["mqtt"] } else { [] },requireAlpn: withAlpn)
    // Socket direction does not choose TLS role: the harness accepts this connection
    // and acts as an independent TLS client. Production callers normally accept sockets.
    let socket = TcpSocket("127.0.0.1",UInt16.parse(args[0]))
    socket.connect()
    socket.readTimeout = Duration.second * 10
    try {
        let buffer = Array<Byte>(31,repeat: 0)
        var request = ""
        var loops: Int64 = 0
        while (request.size < 4) {
            loops += 1
            if (loops > 8192) { throw Exception("TLS read budget exhausted") }
            let count = socket.read(buffer)
            if (count == 0) { server.finishInput() }
            for (data in server.receive(buffer[..count])) { request += String.fromUtf8(data) }
            let output = server.takeHandshakeOutput()
            if (output.size > 0) { socket.write(output) }
        }
        if (!server.established || request != "ping") { throw Exception("TLS server data mismatch") }
        socket.write(server.sealApplicationData("pong".toArray()))
        socket.write(server.closeNotify())
        println("TLS server: verified client Finished and bidirectional application data")
    } finally { server.close(); socket.close() }
    0
}
