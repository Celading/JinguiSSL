package jinguissl_contract.jinguissl.tests

import jinguissl_contract.jinguissl.contract.*

@Test
public class ContractProviderSelfCheckGateTestSuite {
    @TestCase
    public func testContractProviderSmokeSelfCheckDefaultPolicyReady(): Unit {
        let report = contractProviderSmokeSelfCheck()
        @Assert(report.overallReady, true)
        @Assert(report.supportsClientTls, true)
        @Assert(report.supportsX509Verify, true)
        @Assert(report.supportsTlsPrecheck, true)
        @Assert(report.stableServerAttach, false)
        @Assert(report.defaultEligible, false)
        @Assert(report.warnings.contains("provider remains experimental in the current public release line"), true)
    }

    @TestCase
    public func testContractTryRequireProviderSmokeProfileStrictFailsClosed(): Unit {
        let outcome = contractTryRequireProviderSmokeProfile(
            ContractProviderSmokeProfile.ProductionStrict
        )
        @Assert(outcome.ok, false)
        match (outcome.code) {
            case Some(code) =>
                @Assert(code.toString(), "UNSUPPORTED")
            case None =>
                @Fail("strict profile failure should carry contract error code")
        }
        match (outcome.igniteCode) {
            case Some(code) =>
                @Assert(code.toString(), "CRYPTO_UNAVAILABLE")
            case None =>
                @Fail("strict profile failure should carry ignite error code")
        }
        match (outcome.result) {
            case Some(_) =>
                @Fail("strict profile failure should not carry a success result")
            case None => ()
        }
    }

    @TestCase
    public func testContractProviderConsumptionGateHttpAndPlanningRemainUsable(): Unit {
        let httpGate = contractDescribeProviderConsumptionGate(
            ContractProviderConsumptionPath.HttpClientTls
        )
        @Assert(httpGate.readyNow, true)
        @Assert(httpGate.status.toString(), "PROVIDER_CANDIDATE")
        @Assert(httpGate.selectedEntryId, "jinguissl-provider-candidate")
        @Assert(httpGate.fallbackTarget, "stdx-default")
        let planningGate = contractDescribeProviderConsumptionGate(
            ContractProviderConsumptionPath.HttpServerAttachPlanning
        )
        @Assert(planningGate.readyNow, true)
        @Assert(planningGate.status.toString(), "PLANNING_ONLY")
        @Assert(planningGate.guide.requiresUpperLayerAttachGlue, true)
        @Assert(planningGate.selectedReason.contains("attach planning only"), true)
    }

    @TestCase
    public func testContractProviderConsumptionGateStableAttachStaysBlocked(): Unit {
        let gate = contractDescribeProviderConsumptionGate(
            ContractProviderConsumptionPath.HttpServerStableAttach
        )
        @Assert(gate.readyNow, false)
        @Assert(gate.status.toString(), "BLOCKED")
        @Assert(gate.blockedCandidates.size == Int64(1), true)
        @Assert(gate.blockedCandidates[0], "jinguissl-provider-candidate:stable_attach_unpublished")
        match (gate.smokeReadiness) {
            case Some(readiness) =>
                @Assert(readiness.overallReady, false)
            case None =>
                @Fail("stable attach gate should carry mapped smoke readiness")
        }
        let outcome = contractTryRequireProviderConsumptionGate(
            ContractProviderConsumptionPath.HttpServerStableAttach
        )
        @Assert(outcome.ok, false)
        match (outcome.code) {
            case Some(code) =>
                @Assert(code.toString(), "UNSUPPORTED")
            case None =>
                @Fail("blocked stable attach outcome should carry contract error code")
        }
        @Assert(
            outcome.message.contains("stable HTTPS listener attach is not a published jinguissl contract"),
            true
        )
    }

    @TestCase
    public func testContractProviderConsumptionGateSshLibraryShape(): Unit {
        let gate = contractDescribeProviderConsumptionGate(
            ContractProviderConsumptionPath.SshClientLibrary
        )
        @Assert(gate.readyNow, true)
        @Assert(gate.status.toString(), "LIBRARY_CONTRACT")
        @Assert(gate.selectedEntryId, "jinguissl-library-direct")
        @Assert(gate.guide.useProviderSelection, false)
        @Assert(gate.guide.requiresUpperLayerAttachGlue, false)
        match (gate.smokeProfile) {
            case Some(_) =>
                @Fail("ssh library gate should not depend on a smoke profile")
            case None => ()
        }
    }

    @TestCase
    public func testContractResolveProviderFallbackOutcomeMatrix(): Unit {
        let verifyResolution = contractResolveProviderFallbackOutcome(
            ContractProviderFallbackResolutionRequest(
                ContractProviderFallbackCauseCode.TlsVerifyError
            )
        )
        @Assert(verifyResolution.finalOutcome.toString(), "NO_AUTO_FALLBACK")
        @Assert(verifyResolution.fallbackTarget, "")
        @Assert(verifyResolution.mustSurface, true)

        let providerUnavailableOnStable = contractResolveProviderFallbackOutcome(
            ContractProviderFallbackResolutionRequest(
                ContractProviderFallbackCauseCode.ProviderUnavailable,
                alreadyOnStableDefault: true
            )
        )
        @Assert(providerUnavailableOnStable.finalOutcome.toString(), "NO_FALLBACK")

        let cryptoUnavailableOnStable = contractResolveProviderFallbackOutcome(
            ContractProviderFallbackResolutionRequest(
                ContractProviderFallbackCauseCode.CryptoUnavailable,
                alreadyOnStableDefault: true
            )
        )
        @Assert(cryptoUnavailableOnStable.finalOutcome.toString(), "MANUAL_REVIEW")
    }
}
