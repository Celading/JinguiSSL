package jinguissl.tests

import std.fs.File
import jinguissl.contract.*

private func supplyText(name: String): String { String.fromUtf8(File.readFrom("testdata/x509/${name}")) }
private func supplyServer(alpn!: Bool = true): ContractTls13StreamServer {
    ContractTls13StreamServer(supplyText("engine_leaf.pem"), supplyText("policy_leaf_key_pkcs8.pem"),
        alpnProtocols: if (alpn) { ["mqtt"] } else { [] }, requireAlpn: alpn)
}
private func supplyClient(suite: Int64, alpn!: Bool = true): ContractTls13StreamClient {
    ContractTls13StreamClient(supplyText("engine_root.pem"), "www.example.com", "270101000000Z",
        alpnProtocols: if (alpn) { ["mqtt"] } else { [] }, requireAlpn: alpn, cipherSuites: [suite])
}

@Test
public class ContractDownstreamSupplyTestSuite {
    @TestCase
    public func testExtendedCryptoErrorsAndLifecycle(): Unit {
        @Assert(contractBytesToHexLower(contractBlake2s("abc".toArray())),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
        let stream = ContractBlake2sContext(key: Array<Byte>(32, {i => UInt8(i)}), digestLength: 16)
        @Assert(contractBytesToHexLower(stream.finalDigest()), "9536f9b267655743dee97b8a670f9f53")
        stream.destroy()
        try { stream.update([]); @Fail("destroyed hash reused") } catch (_: ContractException) {}
        try { _ = contractBlake2s([], digestLength: 33); @Fail("bad length") } catch (_: ContractException) {}
        try { _ = contractHchacha20([],[]); @Fail("bad HChaCha") } catch (_: ContractException) {}
        let key = Array<Byte>(32, repeat: 7)
        let nonce = Array<Byte>(24, repeat: 8)
        let (cipher,tag) = contractXchacha20Poly1305Encrypt(key,nonce,[UInt8(9)])
        @Assert(contractXchacha20Poly1305Decrypt(key,nonce,cipher,tag), [UInt8(9)])
        tag[0] = tag[0] ^ UInt8(1)
        try { _ = contractXchacha20Poly1305Decrypt(key,nonce,cipher,tag); @Fail("tag accepted") }
        catch (e: ContractException) { @Assert(e.code, ContractErrorCode.VerifyFailed) }
    }

    @TestCase
    public func testAesGcmOwnedContextKnownAnswerAndFailure(): Unit {
        let key = Array<Byte>(16, repeat: 0)
        let context = ContractAesGcmContext(key)
        key[0] = 255
        let nonce = Array<Byte>(12, repeat: 0)
        let plain = Array<Byte>(16, repeat: 0)
        let cipher = Array<Byte>(16, repeat: 0)
        let tag = Array<Byte>(16, repeat: 0)
        let output = Array<Byte>(16, repeat: 77)
        context.encryptInto(nonce,plain,cipher,tag)
        @Assert(contractBytesToHexLower(cipher), "0388dace60b6a392f328c2b971b2fe78")
        @Assert(contractBytesToHexLower(tag), "ab6e47d42cec13bdf53a67b21257bddf")
        context.decryptInto(nonce,cipher,tag,output)
        @Assert(output,plain)
        for (i in 1..20) {
            nonce[11] = UInt8(i)
            context.encryptInto(nonce,plain,cipher,tag)
            context.decryptInto(nonce,cipher,tag,output)
            @Assert(output,plain)
        }
        tag[0] = tag[0] ^ UInt8(1)
        output[0] = 88
        try { context.decryptInto(nonce,cipher,tag,output); @Fail("bad tag accepted") }
        catch (e: ContractException) { @Assert(e.code, ContractErrorCode.VerifyFailed) }
        @Assert(output,plain)
        try { context.encryptInto([],plain,cipher,tag); @Fail("empty nonce") } catch (_: ContractException) {}
        try { context.encryptInto(nonce,plain,[],tag); @Fail("short output") } catch (_: ContractException) {}
        try { context.encryptInto(nonce,plain,cipher,[UInt8(0)],tagLen: 1); @Fail("weak tag") } catch (_: ContractException) {}
        context.destroy(); context.destroy()
        try { context.decryptInto(nonce,cipher,tag,output); @Fail("destroyed AES context") } catch (_: ContractException) {}
    }

    @TestCase
    public func testGenericServerThreeSuitesFragmentationAndClose(): Unit {
        for (suite in [0x1301,0x1302,0x1303]) {
            let server = supplyServer()
            let client = supplyClient(suite)
            for (b in client.takeHandshakeOutput()) { @Assert(server.receive([b]).size,0) }
            let flight = server.takeHandshakeOutput()
            for (b in flight) { @Assert(client.receive([b]).size,0) }
            @Assert(client.authenticated)
            @Assert(!server.established)
            let done = client.takeHandshakeOutput()
            for (b in done) { @Assert(server.receive([b]).size,0) }
            @Assert(server.established)
            @Assert(server.cipherSuite,suite)
            @Assert(server.selectedAlpn(),"mqtt")
            @Assert(server.receive(client.sealApplicationData("ping".toArray()))[0],"ping".toArray())
            @Assert(client.receive(server.sealApplicationData("pong".toArray()))[0],"pong".toArray())
            @Assert(server.receive(client.closeNotify()).size,0)
            @Assert(server.isClosed)
            @Assert(server.takeHandshakeOutput().size > 0)
            try { _ = server.sealApplicationData([]); @Fail("closed server reused") } catch (_: ContractException) {}
        }
    }

    @TestCase
    public func testGenericServerAbsentAlpnAndTruncatedEof(): Unit {
        let server = supplyServer(alpn: false)
        let client = supplyClient(0x1301,alpn: false)
        _ = server.receive(client.takeHandshakeOutput())
        _ = client.receive(server.takeHandshakeOutput())
        _ = server.receive(client.takeHandshakeOutput())
        @Assert(server.established)
        @Assert(server.selectedAlpn(),"")
        try { server.finishInput(); @Fail("EOF without alert") } catch (_: ContractException) {}
        @Assert(server.isClosed)
    }

    @TestCase
    public func testGenericServerRejectsBadFinishedAndEarlyWrite(): Unit {
        let server = supplyServer()
        let client = supplyClient(0x1301)
        try { _ = server.sealApplicationData([]); @Fail("unauthenticated write") } catch (_: ContractException) {}
        _ = server.receive(client.takeHandshakeOutput())
        _ = client.receive(server.takeHandshakeOutput())
        let finished = client.takeHandshakeOutput()
        finished[finished.size-1] = finished[finished.size-1] ^ UInt8(1)
        try { _ = server.receive(finished); @Fail("tampered Finished") } catch (_: ContractException) {}
        @Assert(!server.established)
        @Assert(server.isClosed)
        try { _ = server.receive([]); @Fail("failed server reused") } catch (_: ContractException) {}
    }

    @TestCase
    public func testGenericServerRequiresAlpnAndBounds(): Unit {
        let server = supplyServer()
        let client = supplyClient(0x1301,alpn: false)
        try { _ = server.receive(client.takeHandshakeOutput()); @Fail("required ALPN bypass") } catch (_: ContractException) {}
        @Assert(server.isClosed)
        let oversized = supplyServer()
        try { _ = oversized.receive([UInt8(22),3,1,255,255]); @Fail("oversized record") } catch (_: ContractException) {}
        @Assert(oversized.isClosed)
    }
}
