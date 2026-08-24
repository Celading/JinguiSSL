package jinguissl.tests

import jinguissl.contract.*

@Test
public class ContractSm9TestSuite {
    @TestCase
    public func testSm9SignVerifyAndPairingByteFacade(): Unit {
        let master = contractSm9GenerateSignMasterKeyPair()
        @Assert(master.privateKey.size, CONTRACT_SM9_SCALAR_LEN)
        @Assert(master.publicKey.size, CONTRACT_SM9_G2_LEN)
        @Assert(contractSm9SignMasterPublicFromPrivate(master.privateKey), master.publicKey)
        let identity = "Alice@example.cn".toArray()
        let user = contractSm9ExtractSignUserPrivateKey(master.privateKey, identity)
        let message = "SM9 contract signature".toArray()
        let signature = contractSm9Sign(user, message)
        @Assert(signature.size, CONTRACT_SM9_SIGNATURE_LEN)
        @Assert(contractSm9Verify(master.publicKey, identity, message, signature), true)
        @Assert(
            contractSm9Verify(master.publicKey, identity, "tampered".toArray(), signature),
            false
        )

        let encryptionMaster = contractSm9GenerateEncryptionMasterKeyPair()
        @Assert(
            contractSm9Pairing(encryptionMaster.publicKey, master.publicKey).size,
            CONTRACT_SM9_PAIRING_LEN
        )
        @Assert(contractSm9HashH1(identity).size, CONTRACT_SM9_SCALAR_LEN)
        @Assert(contractSm9HashH2(message).size, CONTRACT_SM9_SCALAR_LEN)
    }

    @TestCase
    public func testSm9IdentityEncryptionAndTamperRejection(): Unit {
        let master = contractSm9GenerateEncryptionMasterKeyPair()
        @Assert(contractSm9EncryptionMasterPublicFromPrivate(master.privateKey), master.publicKey)
        let identity = "Bob@example.cn".toArray()
        let user = contractSm9ExtractEncryptionUserPrivateKey(master.privateKey, identity)
        let plaintext = "SM9 identity-based encryption".toArray()
        let ciphertext = contractSm9Encrypt(master.publicKey, identity, plaintext)
        @Assert(contractSm9Decrypt(user, identity, ciphertext), plaintext)
        let tampered = ciphertext.clone()
        tampered[tampered.size - 1] ^= UInt8(1)
        sm9ContractAssertRejected({ => _ = contractSm9Decrypt(user, identity, tampered) })
    }

    @TestCase
    public func testSm9AuthenticatedKeyExchange(): Unit {
        let master = contractSm9GenerateEncryptionMasterKeyPair()
        let aliceIdentity = "Alice".toArray()
        let bobIdentity = "Bob".toArray()
        let aliceKey = contractSm9ExtractEncryptionUserPrivateKey(
            master.privateKey, aliceIdentity, hierarchy: UInt8(0x02)
        )
        let bobKey = contractSm9ExtractEncryptionUserPrivateKey(
            master.privateKey, bobIdentity, hierarchy: UInt8(0x02)
        )
        let aliceState = contractSm9BeginKeyExchange(
            aliceKey, aliceIdentity, bobIdentity, hierarchy: UInt8(0x02)
        )
        let bobState = contractSm9BeginKeyExchange(
            bobKey, bobIdentity, aliceIdentity, hierarchy: UInt8(0x02)
        )
        let alice = contractSm9CompleteKeyExchange(
            aliceState, bobState.ephemeralPublicKey, true, 32
        )
        let bob = contractSm9CompleteKeyExchange(
            bobState, aliceState.ephemeralPublicKey, false, 32
        )
        @Assert(alice.key, bob.key)
        @Assert(
            contractSm9VerifyKeyExchangeConfirmation(
                alice.expectedPeerConfirmation, bob.sendConfirmation
            ),
            true
        )
        @Assert(
            contractSm9VerifyKeyExchangeConfirmation(
                bob.expectedPeerConfirmation, alice.sendConfirmation
            ),
            true
        )
    }
}

private func sm9ContractAssertRejected(action: () -> Unit): Unit {
    var rejected = false
    try {
        action()
    } catch (_: ContractException) {
        rejected = true
    }
    @Assert(rejected, true)
}
