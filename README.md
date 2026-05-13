# JinguiSSL-contract

`JinguiSSL-contract` 是 Jingui family 未来的 stable facade / contract sibling project target。

## Current State

- `first extraction packet landed`
- `second extraction packet landed`
- `third extraction packet landed`
- `fourth extraction packet landed`
- `fifth extraction packet landed`
- `sixth extraction packet landed`
- `seventh extraction packet landed`
- `eighth extraction packet landed`
- current shape:
  - `contract metadata / capability slice extracted into a buildable static package`
  - `provider/gate metadata and boundary slice extracted into the same target-local package`
  - `provider smoke fixture / baseline / suite slice extracted into the same target-local package`
  - `provider self-check / profile / fallback / consumption gate slice extracted into the same target-local package`
  - `AES readiness / native-bridge / startup slice extracted into the same target-local package`
  - `HTTP / SSH startup readiness / policy / profile slice extracted into the same target-local package`
  - `HTTP startup material / request bundle first slice extracted into the same target-local package`
  - `SSH startup request bundle follow-up slice extracted into the same target-local package`

## Intended Scope

- `src/jinguissl/contract/**`
- stable facade / DTO / outcome / error model
- policy / provider contract wording
- public docs 主入口

## Current Extraction Boundary

当前已按 issue-sized packet 抽出六层 contract truth：

- `ContractErrorCode`
- `ContractException`
- `ContractIgniteCryptoErrorCode`
- `ContractFacadeInfo`
- `contractFacadeInfo()`
- `ContractCapabilityInfo`
- `contractCapabilityInfo()`

随后又补了一张更窄的 provider/gate follow-up packet：

- `ContractProviderServerAttachStatus`
- `ContractProviderErrorPhase`
- `ContractProviderErrorFamily`
- `ContractProviderCapabilityRecord`
- `ContractProviderAttachContractInfo`
- `ContractProviderServerAttachBoundary`
- `ContractProviderErrorDescriptor`
- `ContractProviderFallbackDecision`
- `contractProviderCapabilityRecord()`
- `contractProviderAttachContractInfo()`
- `contractProviderServerAttachBoundary()`

随后又补了一张 provider smoke / baseline / suite packet：

- `contractMapToIgniteCryptoErrorCode()`
- `contractMapExceptionToIgniteCryptoErrorCode()`
- `contractDescribeProviderErrorCode()`
- `contractDescribeProviderContractException()`
- `contractRecommendProviderFallback()`
- `ContractProviderSmokeFixtureCategory`
- `ContractProviderSmokeFixtureInfo`
- `ContractProviderSmokeExecutionMode`
- `ContractProviderSmokeBaselineRequest`
- `ContractProviderSmokeBaselineReport`
- `ContractProviderSmokeBaselineOutcome`
- `ContractProviderSmokeSuiteRequest`
- `ContractProviderSmokeSuiteReport`
- `ContractProviderSmokeSuiteOutcome`
- `contractProviderSmokeFixtureCatalog()`
- `contractRequireProviderSmokeFixture()`
- `contractDescribeProviderSmokeBaseline*`
- `contractDescribeProviderSmokeSuite*`

随后又补了一张 provider self-check / profile / consumption gate packet：

- `ContractProviderSmokeSelfCheckPolicy`
- `ContractProviderSmokeSelfCheckReport`
- `ContractProviderSmokeSelfCheckOutcome`
- `ContractProviderSmokeProfile`
- `ContractProviderSmokeProfileTemplate`
- `ContractProviderConsumptionPath`
- `ContractProviderConsumptionPathGuide`
- `ContractProviderFallbackCauseCode`
- `ContractProviderFallbackOutcome`
- `ContractProviderFallbackOutcomeGuide`
- `ContractProviderFallbackResolutionRequest`
- `ContractProviderFallbackResolution`
- `ContractProviderConsumptionGateStatus`
- `ContractProviderConsumptionGateReport`
- `ContractProviderConsumptionGateOutcome`
- `contractProviderSmokeSelfCheck*`
- `contractDescribeProviderSmokeProfile*`
- `contractDescribeProviderConsumptionPath*`
- `contractDescribeProviderFallbackOutcomeGuide*`
- `contractResolveProviderFallbackOutcome()`
- `contractDescribeProviderConsumptionGate*`

随后又补了一张 AES readiness / native-bridge / startup packet：

- `ContractAesHardwareMountPointInfo`
- `ContractAesHardwareProbeInfo`
- `ContractAesHardwareRoadmapEntry`
- `ContractAesEngineKind`
- `ContractAesEngineInfo`
- `ContractAesEngineResolveOutcome`
- `ContractAesNativeBridgeSpec`
- `ContractAesNativeBridgeContractInfo`
- `ContractAesNativeBridgeCallShapeInfo`
- `ContractAesNativeBridgeDiagnostics`
- `ContractAesNativeBridgeDiagnosticsOutcome`
- `ContractAesBackendReadiness`
- `ContractAesBackendRecommendation`
- `ContractAesStartupSelfCheckReport`
- `ContractAesCurrentReleasePlanReport`
- `contractAesListHardwareMountPoints()`
- `contractAesHardwareRoadmap()`
- `contractAesDefaultHardwareBackendHint()`
- `contractAesProbeHardware()`
- `contractResolveAesEngine()`
- `contractTryResolveAesEngine()`
- `contractRequireAesAcceleratedBackend()`
- `contractInspectAesNativeBridge()`
- `contractTryInspectAesNativeBridge()`
- `contractDescribeAesNativeBridgeCallShape()`
- `contractRecommendAesBackend()`
- `contractAesStartupSelfCheck()`
- `contractAesCurrentReleasePlan()`
- `contractRequireAesCurrentReleasePrimaryBackend()`

随后又补了一张 HTTP / SSH startup readiness / policy / profile packet：

- `ContractHttpSshStartupReadinessReport`
- `ContractHttpSshStartupReadinessOutcome`
- `ContractHttpSshStartupPolicy`
- `ContractHttpSshStartupProfile`
- `ContractHttpSshStartupProfileTemplate`
- `contractHttpSshStartupReadiness()`
- `contractTryHttpSshStartupReadiness()`
- `contractRequireHttpSshStartupReadiness()`
- `contractTryRequireHttpSshStartupReadiness()`
- `contractDescribeHttpSshStartupProfile()`
- `contractListHttpSshStartupProfiles()`
- `contractRequireHttpSshStartupProfile()`
- `contractTryRequireHttpSshStartupProfile()`

随后又补了一张 HTTP startup material / request bundle first packet：

- `ContractX509PinPolicy`
- `ContractX509VerifyResult`
- `ContractX509VerifyOutcome`
- `ContractTlsHttpNegotiationPolicy`
- `ContractTlsHttpNegotiationPolicyValidationResult`
- `ContractTlsHttpNegotiationPolicyValidationOutcome`
- `ContractHttpServerTlsConfigValidationResult`
- `ContractHttpServerTlsConfigValidationOutcome`
- `ContractHttpServerTlsMaterial`
- `ContractHttpServerTlsMaterialOutcome`
- `ContractHttpClientTlsConfigValidationResult`
- `ContractHttpClientTlsConfigValidationOutcome`
- `ContractHttpClientTlsTrustMaterial`
- `ContractHttpClientTlsTrustMaterialOutcome`
- `ContractHttpServerTlsConfigRequest`
- `ContractHttpClientTlsTrustRequest`
- `ContractHttpServerLibraryStartupBundle`
- `ContractHttpServerLibraryStartupOutcome`
- `ContractHttpClientLibraryStartupBundle`
- `ContractHttpClientLibraryStartupOutcome`
- `ContractHttpServerLibraryStartupRequest`
- `ContractHttpClientLibraryStartupRequest`
- `contractComputeLeafPinsFromPem()`
- `contractVerifyServerCertificatePem()`
- `contractVerifyServerCertificateChainPem()`
- `contractTryVerifyServerCertificateChainPem()`
- `contractValidateTlsHttpNegotiationPolicy()`
- `contractTryValidateTlsHttpNegotiationPolicy()`
- `contractValidateHttpServerTlsConfigInput()`
- `contractTryValidateHttpServerTlsConfigInput()`
- `contractValidateHttpServerTlsConfigRequest()`
- `contractTryValidateHttpServerTlsConfigRequest()`
- `contractPrepareHttpServerTlsMaterial()`
- `contractPrepareHttpServerTlsMaterialRequest()`
- `contractTryPrepareHttpServerTlsMaterial()`
- `contractTryPrepareHttpServerTlsMaterialRequest()`
- `contractValidateHttpClientTlsConfigInput()`
- `contractTryValidateHttpClientTlsConfigInput()`
- `contractValidateHttpClientTlsTrustRequest()`
- `contractTryValidateHttpClientTlsTrustRequest()`
- `contractPrepareHttpClientTlsTrustMaterial()`
- `contractPrepareHttpClientTlsTrustMaterialRequest()`
- `contractTryPrepareHttpClientTlsTrustMaterial()`
- `contractTryPrepareHttpClientTlsTrustMaterialRequest()`
- `contractPrepareHttpServerLibraryStartupRequest()`
- `contractTryPrepareHttpServerLibraryStartupRequest()`
- `contractPrepareHttpClientLibraryStartupRequest()`
- `contractTryPrepareHttpClientLibraryStartupRequest()`

随后又补了一张 SSH startup request bundle follow-up packet：

- `ContractSshNegotiatedAlgorithms`
- `ContractSshKexExchangeTranscript`
- `ContractSshHostVerificationPolicy`
- `ContractSshClientInitialHandshakeX25519Request`
- `ContractSshServerLibraryStartupX25519RsaPkcs8Request`
- `ContractSshServerLibraryStartupX25519EcdsaPkcs8Request`
- `ContractSshServerLibraryStartupX25519Ed25519SeedRequest`
- `ContractSshClientLibraryStartupX25519Request`
- `ContractSshServerLibraryStartupBundle`
- `ContractSshClientLibraryStartupBundle`
- `ContractSshServerLibraryStartupOutcome`
- `ContractSshClientLibraryStartupOutcome`
- `contractPrepareSshServerLibraryStartupX25519RsaPkcs8Request()`
- `contractTryPrepareSshServerLibraryStartupX25519RsaPkcs8Request()`
- `contractPrepareSshServerLibraryStartupX25519EcdsaPkcs8Request()`
- `contractTryPrepareSshServerLibraryStartupX25519EcdsaPkcs8Request()`
- `contractPrepareSshServerLibraryStartupX25519Ed25519SeedRequest()`
- `contractTryPrepareSshServerLibraryStartupX25519Ed25519SeedRequest()`
- `contractPrepareSshClientLibraryStartupX25519Request()`
- `contractTryPrepareSshClientLibraryStartupX25519Request()`

这张 follow-up packet 当前继续保持诚实边界：

- startup-facing input DTO 与 facade 已 target-local 化
- bundle 里的 SSH handshake/runtime result 仍暂时承接 old live source contract types
- 这不代表 whole SSH runtime/result cluster 已完成迁移

当前 target-local package topology 为：

- `jinguissl_contract`
- `jinguissl_contract.jinguissl`
- `jinguissl_contract.jinguissl.contract`
- `jinguissl_contract.jinguissl.tests`

这轮还没有抽：

- SSH handshake/runtime result whole cluster
- 旧 live source `contract.cj` 的其余大体量 surface
- public stable import path 退役

## Current Live Source

当前真实源码与文档 owner 仍在：

- `/Users/cinyu/Documents/Work0/CureateX/jinkuiSSL/jinguiSSL`

## Validation

当前目标完成判据为：

```bash
cjpm build
cjpm test
```

## Notes

- 这张 target lane 当前证明的是 contract sibling project 已经不是空 skeleton。
- 这不表示 `jinguissl.contract.*` 的公开 import 已迁移到这个 target project。
- 当前 AES facade 仍通过 `cjpm.toml` 临时依赖 old live source `../../jinkuiSSL/jinguiSSL`，直到 `JinguiSSL-core` 起盘。
- 当前 extracted slice 已覆盖 metadata、provider/gate、provider smoke baseline/suite、provider self-check/profile/consumption gate、AES readiness/native-bridge/startup、HTTP/SSH startup readiness/policy/profile、HTTP startup material/request bundle first、SSH startup request bundle follow-up 八层，但还不是整份 contract 主体。
