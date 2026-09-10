package jinguissl.tests

import std.fs.File
import jinguissl.contract.*

@Test
public class ContractBridgeSshFacadeTestSuite {
    @TestCase
    public func testRsaHostSigningUsesContractOwnedKey(): Unit {
        let privateKey = contractX509ParseRsaPrivateKeyPkcs8Pem(
            String.fromUtf8(File.readFrom("testdata/x509/rsa_2048_pkcs8.pem"))
        )
        let exchangeHash = contractSha256("bridge-ssh-contract-boundary".toArray())
        let encodedHostKey = contractBridgeSshEncodeRsaHostPublicKey(privateKey.publicKey)
        let signature = contractBridgeSshSignExchangeHashRsa(privateKey, exchangeHash)
        let prepared = contractBridgePrepareSshHostSigningRsa(privateKey, exchangeHash)

        @Assert(encodedHostKey.size > 0, true)
        @Assert(signature.size > 0, true)
        @Assert(prepared.serverHostKey, encodedHostKey)
        @Assert(prepared.hostSignature.size > 0, true)
        @Assert(prepared.hostKeySha256.size, 32)

        let outcome = contractBridgeTryPrepareSshHostSigningRsa(privateKey, exchangeHash)
        @Assert(outcome.ok, true)
    }
}
