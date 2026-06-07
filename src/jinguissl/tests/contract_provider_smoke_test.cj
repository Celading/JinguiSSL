package JinguiSSL.jinguissl.tests

import JinguiSSL.jinguissl.contract.*

@Test
public class ContractProviderSmokeTestSuite {
    @TestCase
    public func testContractProviderSmokeFixtureCatalogShape(): Unit {
        let catalog = contractProviderSmokeFixtureCatalog()
        @Assert(catalog.size > 0, true)
        let successFixture = contractRequireProviderSmokeFixture(" success-x509-policy-chain ")
        @Assert(successFixture.category.toString(), "SUCCESS")
        let unavailableFixture = contractRequireProviderSmokeFixture("provider-not-linked")
        match (unavailableFixture.expectedFamily) {
            case Some(family) =>
                @Assert(family.toString(), "PROVIDER_UNAVAILABLE")
            case None =>
                @Fail("provider-not-linked fixture should carry expected family")
        }
    }

    @TestCase
    public func testContractProviderSmokeSuccessBaselineShape(): Unit {
        let report = contractDescribeProviderSmokeBaseline("success-x509-policy-chain")
        @Assert(report.expectedSuccess, true)
        @Assert(report.executionMode.toString(), "VERIFY_PATH")
        @Assert(report.warnings.size > 0, true)
        match (report.expectedDescriptor) {
            case Some(_) =>
                @Fail("success baseline should not carry expected descriptor")
            case None => ()
        }
        match (report.expectedFallback) {
            case Some(_) =>
                @Fail("success baseline should not carry fallback decision")
            case None => ()
        }
    }

    @TestCase
    public func testContractProviderSmokeFailureBaselineShape(): Unit {
        let report = contractDescribeProviderSmokeBaseline("verify-hostname-mismatch")
        @Assert(report.expectedSuccess, false)
        @Assert(report.executionMode.toString(), "VERIFY_PATH")
        match (report.expectedDescriptor) {
            case Some(descriptor) =>
                @Assert(descriptor.family.toString(), "TLS_VERIFY_ERROR")
                @Assert(descriptor.phase.toString(), "TLS_VERIFY")
                @Assert(descriptor.fallbackSuggested, false)
                match (descriptor.code) {
                    case Some(code) =>
                        @Assert(code.toString(), "VERIFY_FAILED")
                    case None =>
                        @Fail("failure baseline descriptor should carry code")
                }
            case None =>
                @Fail("failure baseline should carry expected descriptor")
        }
        match (report.expectedFallback) {
            case Some(fallback) =>
                @Assert(fallback.fallbackSuggested, false)
                @Assert(fallback.mustSurface, true)
            case None =>
                @Fail("failure baseline should carry fallback decision")
        }
    }

    @TestCase
    public func testContractProviderSmokeSuiteCountsStayConsistent(): Unit {
        let suite = contractDescribeProviderSmokeSuiteRequest(
            ContractProviderSmokeSuiteRequest(
                fixtureIds: [
                    "success-x509-policy-chain",
                    "provider-not-linked",
                    "attach-stable-listener-unpublished"
                ]
            )
        )
        @Assert(suite.totalFixtureCount == Int64(3), true)
        @Assert(suite.successFixtureCount == Int64(1), true)
        @Assert(suite.failureFixtureCount == Int64(2), true)
        @Assert(suite.verifyPathCount == Int64(1), true)
        @Assert(suite.providerSelectionPathCount == Int64(1), true)
        @Assert(suite.metadataOnlyCount == Int64(1), true)
        @Assert(
            suite.warnings.contains(
                "metadata-only smoke baselines should be asserted through contract descriptors instead of being counted as live handshake regressions"
            ),
            true
        )
    }

    @TestCase
    public func testContractTryDescribeProviderSmokeBaselineRequestMapsBadInput(): Unit {
        let outcome = contractTryDescribeProviderSmokeBaselineRequest(
            ContractProviderSmokeBaselineRequest("missing-fixture")
        )
        @Assert(outcome.ok, false)
        match (outcome.code) {
            case Some(code) =>
                @Assert(code.toString(), "BAD_INPUT")
            case None =>
                @Fail("failure outcome should carry contract error code")
        }
        match (outcome.igniteCode) {
            case Some(code) =>
                @Assert(code.toString(), "BAD_ENVELOPE")
            case None =>
                @Fail("failure outcome should carry ignite error code")
        }
        match (outcome.result) {
            case Some(_) =>
                @Fail("failure outcome should not carry result")
            case None => ()
        }
    }
}
