package jinguissl.tests

import std.unittest.*
import std.unittest.testmacro.*
import jinguissl.contract.*

@Test
public class ContractDtlsTestSuite {
    @TestCase
    public func testFacadeOnlyAuthenticationSecretsOwnershipAndClose(): Unit {
        for (profile in [Int64(7), Int64(1)]) {
            let a = ContractDtlsIdentity.generate("client", "260101000000Z", "360101000000Z")
            let b = ContractDtlsIdentity.generate("server", "260101000000Z", "360101000000Z")
            let client = ContractDtlsSession(ContractDtlsRole.Client, a, b.fingerprintSha256(), [UInt8(1)], srtpProfiles: [profile])
            let server = ContractDtlsSession(ContractDtlsRole.Server, b, a.fingerprintSha256(), [UInt8(1)], srtpProfiles: [profile])
            a.destroy(); b.destroy()
            var denied = false
            try { _ = client.exportSrtp() } catch (_: ContractException) { denied = true }
            @Assert(denied)
            client.start(0); server.start(0)
            for (i in 1..20) {
                for (packet in client.takeOutput()) { _ = server.receive(packet, i * 100) }
                for (packet in server.takeOutput()) { _ = client.receive(packet, i * 100) }
                if (client.authenticated && server.authenticated) { break }
            }
            @Assert(client.authenticated && server.authenticated)
            @Assert(client.selectedSrtpProfile(), profile)
            @Assert(client.peerCertificateDer(), b.certificateDer())
            let first = client.exportSrtp(); let second = client.exportSrtp(); let peer = server.exportSrtp()
            let changed = first.clientWriteKey(); changed[0] ^= UInt8(1)
            @Assert(first.clientWriteKey(), second.clientWriteKey())
            @Assert(first.serverWriteSalt(), peer.serverWriteSalt())
            first.destroy(); @Assert(first.isDestroyed && !second.isDestroyed)
            denied = false
            try { _ = first.clientWriteKey() } catch (_: ContractException) { denied = true }
            @Assert(denied)
            @Assert(server.receive(client.sealApplicationData("media-control".toArray()), 3000)[0], "media-control".toArray())
            client.closeNotify(); @Assert(client.isClosed && !client.authenticated)
            for (packet in client.takeOutput()) { _ = server.receive(packet, 3001) }
            @Assert(server.isClosed && server.takeOutput().size == 1)
            @Assert(client.takeOutput().size, 0)
            denied = false
            try { _ = server.exportSrtp() } catch (_: ContractException) { denied = true }
            @Assert(denied)
            second.destroy(); peer.destroy(); client.close(); server.close()
        }
    }
    @TestCase
    public func testFacadeInvalidInputAndClosedStateUseContractException(): Unit {
        var rejected = false
        try { _ = ContractDtlsIdentity("not a key", []) } catch (_: ContractException) { rejected = true }
        @Assert(rejected)
        let id = ContractDtlsIdentity.generate("peer", "260101000000Z", "360101000000Z")
        rejected = false
        try { _ = ContractDtlsSession(ContractDtlsRole.Client, id, "gg", [UInt8(1)]) }
        catch (_: ContractException) { rejected = true }
        @Assert(rejected)
        let session = ContractDtlsSession(ContractDtlsRole.Client, id, id.fingerprintSha256(), [UInt8(1)])
        session.close()
        rejected = false
        try { session.start(0) } catch (_: ContractException) { rejected = true }
        @Assert(rejected)
        rejected = false
        try { _ = session.receive([], 0) } catch (_: ContractException) { rejected = true }
        @Assert(rejected)
        id.destroy()
        rejected = false
        try { _ = ContractDtlsSession(ContractDtlsRole.Client, id, id.fingerprintSha256(), [UInt8(1)]) }
        catch (_: ContractException) { rejected = true }
        @Assert(rejected)
    }
}
