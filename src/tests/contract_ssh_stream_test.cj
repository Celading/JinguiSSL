package jinguissl.tests

import std.fs.File
import jinguissl.contract.*
// Provider fixture only; the public request/channel exposes no Core types.
import jinguissl_core.crypto.ssh.{SshKexExchangeTranscript,SshNegotiatedAlgorithms,
    SshPacketProtectionLayer,sshCompleteServerInitialHandshakeX25519Ecdsa}
import jinguissl_core.crypto.x509.x509ParseEcPrivateKeyPkcs8Pem
import jinguissl_core.crypto.digest.sha256

@Test
public class ContractSshStreamTestSuite {
    @TestCase
    public func testOwnedVerifiedStreamFragmentationCoalescingAndFailure(): Unit {
        for (cipher in ["aes128-ctr","aes256-ctr","aes128-gcm@openssh.com","aes256-gcm@openssh.com","chacha20-poly1305@openssh.com"]) {
            let mac = if (cipher.endsWith("-ctr")) { "hmac-sha2-256" } else { "none" }
            let ck = Array<Byte>(32,repeat: 7)
            let sk = Array<Byte>(32,repeat: 8)
            let transcript = ContractSshKexExchangeTranscript("SSH-2.0-client\r\n".toArray(),"SSH-2.0-server\r\n".toArray(),
                contractSshBuildDefaultKexInitPayload(),contractSshBuildDefaultKexInitPayload())
            let initMessage = contractSshBuildKexEcdhInitX25519(ck).encodedInit
            let newKeys = contractSshEncodeNewKeys()
            let algorithms = ContractSshNegotiatedAlgorithms("curve25519-sha256","ecdsa-sha2-nistp256",cipher,cipher,mac,mac)
            let server = sshCompleteServerInitialHandshakeX25519Ecdsa(
                SshKexExchangeTranscript(transcript.clientBannerLine,transcript.serverBannerLine,
                    transcript.clientKexInitPayload,transcript.serverKexInitPayload),sk,initMessage,
                x509ParseEcPrivateKeyPkcs8Pem(String.fromUtf8(File.readFrom("testdata/x509/policy_leaf_key_pkcs8.pem"))),
                SshNegotiatedAlgorithms("curve25519-sha256","ecdsa-sha2-nistp256",cipher,cipher,mac,mac,"none","none"),newKeys,newKeys)
            let request = ContractSshClientInitialHandshakeX25519Request(transcript,ck,initMessage,server.encodedReply,
                algorithms,newKeys,newKeys,policy: ContractSshHostVerificationPolicy(
                    expectedHostKeySha256: sha256(server.kexResult.serverHostKey),requireKnownHost: true))
            let client = contractSshOpenClientPacketStream(request,sentPacketCount: 3,receivedPacketCount: 4)
            let keys = server.coordinator.derivedKeys()
            let peer = SshPacketProtectionLayer(keys.serverToClient,keys.clientToServer,initialWriteSequence: 4,initialReadSequence: 3)
            @Assert(client.hostVerification.hostSignatureVerified)
            @Assert(peer.open(client.seal("ping".toArray())).payload,"ping".toArray())
            let wire = peer.seal("pong".toArray())
            for (i in 0..wire.size-1) { @Assert(client.receive([wire[i]]).size,0); @Assert(client.readSequence,4) }
            @Assert(client.receive([wire[wire.size-1]])[0],"pong".toArray())
            @Assert(client.readSequence,5)
            let first = peer.seal("one".toArray())
            let second = peer.seal("two".toArray())
            let combined = Array<Byte>(first.size+second.size, {i => if (i < first.size) { first[i] } else { second[i-first.size] }})
            let messages = client.receive(combined)
            @Assert(messages.size,2)
            @Assert(messages[0],"one".toArray())
            @Assert(messages[1],"two".toArray())
            @Assert(client.readSequence,7)
            let bad = peer.seal("bad".toArray())
            bad[bad.size-1] = bad[bad.size-1] ^ UInt8(1)
            try { _ = client.receive(bad); @Fail("tampered SSH packet") } catch (_: ContractException) {}
            @Assert(client.isClosed)
            try { _ = client.receive([]); @Fail("terminal stream reused") } catch (_: ContractException) {}
            try { _ = contractSshOpenClientPacketStream(request,sentPacketCount: 0,receivedPacketCount: 3); @Fail("lost packet count") }
            catch (_: ContractException) {}
            let truncated = contractSshOpenClientPacketStream(request,sentPacketCount: 3,receivedPacketCount: 4)
            _ = truncated.receive([wire[0]])
            try { truncated.finishInput(); @Fail("truncated EOF") } catch (_: ContractException) {}
            @Assert(truncated.isClosed)
        }
    }
}
