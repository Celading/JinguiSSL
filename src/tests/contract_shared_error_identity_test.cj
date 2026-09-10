package jinguissl.tests

import std.collection.HashMap
import jinguissl.contract as stable
import jinguissl.live as legacy

@Test
public class ContractSharedErrorIdentityTestSuite {
    @TestCase
    public func testLegacyErrorHasCanonicalContractIdentity(): Unit {
        let oldName: legacy.ContractErrorCode = stable.ContractErrorCode.BadInput
        let error: stable.ContractException = legacy.ContractException(oldName, "identity")
        @Assert(error.code, stable.ContractErrorCode.BadInput)
        @Assert(error.message, "identity")
        try {
            _ = legacy.contractEncryptEnvelopeV1(legacy.ContractAeadAlgorithm.Aes256Gcm,
                "", Array<Byte>(32, repeat: 1), [1])
            @Fail("invalid envelope key id must fail")
        } catch (e: stable.ContractException) {
            @Assert(e.code, stable.ContractErrorCode.BadInput)
        }
    }

    @TestCase
    public func testIndependentEnvelopeKeysDoNotShareContexts(): Unit {
        for (i in 0..32) {
            let key = Array<Byte>(32, repeat: UInt8(i))
            let ring = HashMap<String, Array<Byte>>()
            ring["sample"] = key
            let message = [UInt8(i), UInt8(42)]
            let envelope = legacy.contractEncryptEnvelopeV1(
                legacy.ContractAeadAlgorithm.Aes256Gcm, "sample", key, message)
            @Assert(legacy.contractDecryptEnvelopeV1(envelope, ring), message)
            ring["sample"] = Array<Byte>(32, repeat: UInt8(i + 1))
            try {
                _ = legacy.contractDecryptEnvelopeV1(envelope, ring)
                @Fail("wrong key must fail")
            } catch (_: stable.ContractException) {}
        }
    }
}
