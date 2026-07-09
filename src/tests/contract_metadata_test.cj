package jinguissl.tests

import jinguissl.contract.*

@Test
public class ContractMetadataTestSuite {
    @TestCase
    public func testContractFacadeInfoShape(): Unit {
        let info = contractFacadeInfo()
        @Assert(info.apiVersion, "1.0.0")
        @Assert(info.stabilityLevel, "L1")
        @Assert(info.freezeDate, "2026-03-24")
        @Assert(info.stableDomains.size > 0, true)
        @Assert(info.importRule.contains("jinguissl.contract.*"), true)
    }

    @TestCase
    public func testContractCapabilityInfoShape(): Unit {
        let info = contractCapabilityInfo()
        @Assert(info.stableDomains.size > 0, true)
        @Assert(info.httpTlsFeatures.contains("tls13-x25519"), true)
        @Assert(info.sshFeatures.contains("x25519-kex"), true)
        @Assert(info.x509Features.contains("certificate-chain-verify"), true)
        @Assert(info.directStdxTlsServerConfigBridge, false)
        @Assert(info.notes.size > 0, true)
    }

    @TestCase
    public func testContractFacadeInfoRejectsEmptyVersion(): Unit {
        try {
            _ = ContractFacadeInfo("", "L1", "2026-03-24", ["tls13"], "import jinguissl.contract.* only")
            @Fail("empty version should be rejected")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }
    }

    @TestCase
    public func testContractErrorAndIgniteCodesStayStable(): Unit {
        @Assert(ContractErrorCode.VerifyFailed.toString(), "VERIFY_FAILED")
        @Assert(ContractIgniteCryptoErrorCode.DecryptFailed.toString(), "DECRYPT_FAILED")
    }
}

// Supplemental tests added for enriched coverage
@Test
public class ContractSupplementaryTestSuite {
    @TestCase
    public func testContractMd5KnownVector(): Unit {
        let empty: Array<Byte> = []
        let digest = contractMd5(empty)
        @Assert(contractBytesToHexLower(digest), "d41d8cd98f00b204e9800998ecf8427e")
    }

    @TestCase
    public func testContractSha1KnownVector(): Unit {
        let empty: Array<Byte> = []
        let digest = contractSha1(empty)
        @Assert(contractBytesToHexLower(digest), "da39a3ee5e6b4b0d3255bfef95601890afd80709")
    }

    @TestCase
    public func testContractChacha20Poly1305AlgorithmName(): Unit {
        let name = contractChacha20Poly1305AlgorithmName()
        @Assert(name, "CHACHA20-POLY1305")
    }

    @TestCase
    public func testContractMapToIgniteCryptoErrorCode(): Unit {
        @Assert(contractMapToIgniteCryptoErrorCode(ContractErrorCode.BadInput).toString(), "BAD_ENVELOPE")
    }

    @TestCase
    public func testContractHttpSshStartupProfilesCount(): Unit {
        let profiles = contractListHttpSshStartupProfiles()
        @Assert(profiles.size, 6)
    }

    @TestCase
    public func testContractSmCapability(): Unit {
        let info = contractSmCapability()
        @Assert(info.sm3DigestLen, 32)
    }

    @TestCase
    public func testContractKemProfile(): Unit {
        let profile = contractKemProfile()
        @Assert(profile.available, false)
    }

    @TestCase
    public func testContractEccCapability(): Unit {
        let info = contractEccCapability()
        @Assert(info.available, true)
    }

    @TestCase
    public func testContractEd25519SigningCapability(): Unit {
        let info = contractEd25519SigningCapability()
        @Assert(info.seedLen, 32)
    }

    @TestCase
    public func testContractRsaCapability(): Unit {
        let info = contractRsaCapability()
        @Assert(info.available, true)
    }
}
