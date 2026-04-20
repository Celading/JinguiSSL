# jinguiSSL Provider Contract

## Goal

这份文档服务于 provider 选择层，而不是应用层。

当前定位固定为：

- `jinguissl` 是一个可被 `lisi` 吸收的 TLS / crypto provider 候选
- 当前已具备稳定的 precheck / material preparation / verify / error descriptor contract
- 当前**不是**默认 HTTPS listener 路径

## Stable Contract Helpers

当前公开稳定的 provider 侧 helper：

- `contractProviderCapabilityRecord()`
- `contractProviderAttachContractInfo()`
- `contractProviderServerAttachBoundary()`
- `ContractProviderSmokeFixtureCategory`
- `ContractProviderSmokeFixtureInfo`
- `ContractProviderSmokeExecutionMode`
- `ContractProviderSmokeBaselineRequest`
- `ContractProviderSmokeBaselineReport`
- `ContractProviderSmokeBaselineOutcome`
- `ContractProviderSmokeSuiteRequest`
- `ContractProviderSmokeSuiteReport`
- `ContractProviderSmokeSuiteOutcome`
- `ContractProviderSmokeSelfCheckPolicy`
- `ContractProviderSmokeSelfCheckReport`
- `ContractProviderSmokeSelfCheckOutcome`
- `ContractProviderSmokeProfile`
- `ContractProviderSmokeProfileTemplate`
- `ContractProviderConsumptionPath`
- `ContractProviderConsumptionPathGuide`
- `ContractProviderConsumptionGateStatus`
- `ContractProviderConsumptionGateReport`
- `ContractProviderConsumptionGateOutcome`
- `ContractProviderFallbackCauseCode`
- `ContractProviderFallbackOutcome`
- `ContractProviderFallbackOutcomeGuide`
- `ContractProviderFallbackResolutionRequest`
- `ContractProviderFallbackResolution`
- `contractProviderSmokeFixtureCatalog()`
- `contractRequireProviderSmokeFixture(...)`
- `contractDescribeProviderSmokeBaseline(...)`
- `contractDescribeProviderSmokeBaselineRequest(...)`
- `contractTryDescribeProviderSmokeBaselineRequest(...)`
- `contractDescribeProviderSmokeSuite()`
- `contractDescribeProviderSmokeSuiteRequest(...)`
- `contractTryDescribeProviderSmokeSuiteRequest(...)`
- `contractProviderSmokeSelfCheck(...)`
- `contractRequireProviderSmokeSelfCheck(...)`
- `contractTryProviderSmokeSelfCheck(...)`
- `contractTryRequireProviderSmokeSelfCheck(...)`
- `contractDescribeProviderSmokeProfile(...)`
- `contractListProviderSmokeProfiles()`
- `contractRequireProviderSmokeProfile(...)`
- `contractTryRequireProviderSmokeProfile(...)`
- `contractDescribeProviderConsumptionPath(...)`
- `contractListProviderConsumptionPaths()`
- `contractDescribeProviderConsumptionGate(...)`
- `contractListProviderConsumptionGates()`
- `contractRequireProviderConsumptionGate(...)`
- `contractTryRequireProviderConsumptionGate(...)`
- `contractDescribeProviderFallbackOutcomeGuide(...)`
- `contractListProviderFallbackOutcomeGuides()`
- `contractResolveProviderFallbackOutcome(...)`
- `contractDescribeProviderErrorCode(...)`
- `contractDescribeProviderContractException(...)`
- `contractDescribeProviderCryptoException(...)`
- `contractRecommendProviderFallback(...)`
- `ContractTlsPlaintextRecordRequest`
- `contractTlsEncodePlaintextRecord(...)`
- `contractTlsEncodePlaintextRecordRequest(...)`

## Capability Record

当前 `0.6.21` provider 记录：

- `providerId`: `jinguissl`
- `providerVersion`: `0.6.21`
- `platformScope`: `primary darwin/aarch64; compile-target linux/ohos aarch64; x86_64 deferred to 0.7; loongarch64/riscv64 reserved skeletons`
- `cjScope`: `cjc >= 1.1.0`
- `supportsClientTls`: `true`
- `supportsServerTlsAttach`: `false`
- `supportsX509Verify`: `true`
- `supportsAlpnH2`: `true`
- `supportsMtls`: `false`
- `supportsSessionCache`: `true`
- `experimental`: `true`
- `defaultEligible`: `false`

当前 `unsupportedReasons`：

- 稳定的 server-side TLS attach contract 尚未公开
- 不提供直接 `stdx.net.tls.TlsServerConfig` bridge
- 当前发布线仍是 provider-candidate，不应表述为默认 HTTPS 路径

## Attach Contract

### TLS Precheck Inputs

当前稳定 precheck 侧建议字段：

- `serverName`
- `alpnProtocols`
- `certificatePem`
- `privateKeyPem`
- `trustAnchorsPem`
- `verifyMode`
- `handshakeTimeoutMs`

### TLS Attach Inputs

当前 attach 字段只作为 provider planning contract 保留：

- `serverName`
- `alpnProtocols`
- `certificatePem`
- `privateKeyPem`
- `clientAuthPolicy`
- `sessionTicketPolicy`
- `handshakeTimeoutMs`

结论：

- 这些字段已可用于上层 planning / 记录
- 但本仓不保证稳定的最终 attach 落点

### X.509 Verify Inputs

- `peerCertificatePem`
- `peerChainPem`
- `trustAnchorsPem`
- `expectedHost`
- `verifyMode`
- `pins`

### Failure Fields

provider 侧建议上层至少记录：

- `family`
- `phase`
- `retryable`
- `fallbackSuggested`
- `contractCode`
- `igniteCode`
- `message`

## Current Server Attach Boundary

`contractProviderServerAttachBoundary()` 当前固定返回：

- `status = PRECHECK_ONLY`
- `stableAttach = false`
- `blockingLayer = stdx contract / attach bridge`
- `recommendedFallback = fallback to stdx through lisi and keep jinguissl as provider-candidate only`

这意味着：

- `jinguissl` 目前可以稳定提供 precheck、material preparation、client TLS、X.509 verify
- `jinguissl` 目前不能在公开契约上承诺 server-side attach
- 真正的 attach、fallback 与记录应由 `lisi` 负责

对于 HTTP client 首包边界，当前 contract 语义固定为：

- `contractTls13BuildHttpClientHelloX25519(...)` 返回的是握手报文本体；
- 若上层要把它直接发到 socket，应先用 `contractTlsEncodePlaintextRecord(...)` 包成 `HANDSHAKE` record；
- 这只是 client-side first-flight 打包 helper，不改变 server attach 的公开边界。
- 若你要自己实现这一层接口握手，直接看：
  - `HANDSHAKE_INTERFACE_GUIDE.md`
  - `examples/handshake-interface-demo/`
  - `examples/http-client-consumption-smoke/`（聚焦 `HTTP_CLIENT_TLS` 的 gate、fallback 与 verified-session smoke）

## Consumption Paths

当前建议上层直接消费：

- `contractDescribeProviderConsumptionPath(...)`
- `contractListProviderConsumptionPaths()`
- `contractDescribeProviderConsumptionGate(...)`
- `contractListProviderConsumptionGates()`
- `contractRequireProviderConsumptionGate(...)`
- `contractTryRequireProviderConsumptionGate(...)`

当前固定的消费路径解释：

- `HTTP_CLIENT_TLS`
  - 可以尝试 `jinguissl`
  - 仍属于 provider-candidate 路径，不等于默认切换
  - 推荐 smoke profile：`provider-candidate`
- `HTTP_SERVER_ATTACH_PLANNING`
  - 可以尝试 `jinguissl`
  - 但只到 `precheck + material preparation + attach planning`
  - 推荐 smoke profile：`attach-planning`
  - focused example：`examples/http-server-attach-planning-smoke/`
- `HTTP_SERVER_STABLE_ATTACH`
  - 当前不允许当作公开稳定路径尝试
  - 推荐继续停在 `stdx-default`
  - 推荐 smoke profile：`default-https-eligible`（当前应失败关闭）
- `SSH_CLIENT_LIBRARY`
  - 可以直接消费 `jinguissl.contract.*`
  - 这不是 `stdx` TLS attach 问题，而是稳定库面
- `SSH_SERVER_LIBRARY`
  - 可以直接消费 `jinguissl.contract.*`
  - 这同样不是 `stdx.net.tls.TlsServerConfig` bridge 问题

如果你要把 SSH 握手接到自己的上层接口，而不是只做 capability 判断，也直接看：

- `HANDSHAKE_INTERFACE_GUIDE.md`
- `examples/handshake-interface-demo/`
- `examples/ssh-library-consumption-smoke/`（聚焦 `SSH_CLIENT_LIBRARY / SSH_SERVER_LIBRARY` 的 gate、startup 与 runtime smoke）

这里对 `buildTlsAttachPlan(...)` 的公开解释固定为：

- 在 HTTP client 路径上，它可以被看作真实 provider 尝试计划；
- 在 HTTP server 路径上，它当前只表示 planning contract，不表示稳定 listener attach 已经存在；
- 在 SSH 路径上，它不适用，SSH 应直接消费 `jinguissl.contract.*` 的 handshake/runtime facade。

## Consumption Gate

若上层不想自己拼装：

- path guide
- smoke profile
- smoke readiness
- fallback target
- 当前 selected reason

则可以直接消费 `contractDescribeProviderConsumptionGate(...)` 或 `contractRequireProviderConsumptionGate(...)`。

如果你想看一条聚焦 `HTTP_CLIENT_TLS` 的运行样例，而不是一次性读完整个 handshake demo，也可以直接跑：

- `examples/http-client-consumption-smoke/`

如果你想看一条聚焦 `SSH_CLIENT_LIBRARY / SSH_SERVER_LIBRARY` 的运行样例，而不是一次性读完整个 handshake demo，也可以直接跑：

- `examples/ssh-library-consumption-smoke/`

当前 gate status 含义固定为：

- `PROVIDER_CANDIDATE`
  - 当前公开为 provider-candidate 路径
  - `readyNow = true` 时表示上层可尝试 `jinguissl`，但仍应保留 `stdx-default` fallback
- `PLANNING_ONLY`
  - 当前公开为 planning-only 路径
  - `readyNow = true` 只表示可做 precheck / material preparation / planning，不表示可直接完成 listener attach
- `LIBRARY_CONTRACT`
  - 当前公开为稳定库面
  - 适用于 SSH client/server 这类不依赖 provider attach glue 的路径
- `BLOCKED`
  - 当前不是公开稳定路径
  - `contractRequireProviderConsumptionGate(...)` 应直接失败关闭

当前 gate report 同时固定补齐：

- `providerId`
  - 当前固定返回 `jinguissl`
- `selectedEntryId`
  - `readyNow = true` 时返回当前可消费的 provider entry
  - `readyNow = false` 时返回空字符串，避免把 blocked / fail-closed 路径伪装成已选中
- `candidateOrder`
  - 当前按 `jinguissl` provider entry 在前、稳定 fallback 在后给出固定顺序
- `blockedCandidates`
  - 当前用结构化 `entry:reason` 形式记录 blocked / smoke-not-ready 原因
- `releasePath`
  - 便于上层把 provider gate 直接映射到更高层的 release/observe 语义
  - 当前仅返回：
    - `experimental-only`
    - `library-direct`
    - `unsupported`
- `riskLevel`
  - 当前固定返回：
    - provider-candidate / planning-only => `medium`
    - library-contract => `low`
    - blocked => `high`
- `fallbackChain`
  - 当前若仍建议回到稳定默认路径，则返回：
    - `["stdx-default"]`
  - 对 SSH library-contract 这类稳定库面，当前返回空链
- `observabilityTags`
  - 当前固定补齐 `provider_id`、`provider_entry`、`selected_entry`、`path`、`consumer_kind`、`public_path`、`release_path`、`risk_level`、`ready_now` 等标签

当前固定 gate 结果：

- `HTTP_CLIENT_TLS`
  - `status = PROVIDER_CANDIDATE`
  - `publicPath = provider-candidate`
  - 绑定 smoke profile：`provider-candidate`
- `HTTP_SERVER_ATTACH_PLANNING`
  - `status = PLANNING_ONLY`
  - `publicPath = attach-planning`
  - 绑定 smoke profile：`attach-planning`
- `HTTP_SERVER_STABLE_ATTACH`
  - `status = BLOCKED`
  - `publicPath = blocked`
  - 绑定 smoke profile：`default-https-eligible`，当前应失败关闭
- `SSH_CLIENT_LIBRARY`
  - `status = LIBRARY_CONTRACT`
  - `publicPath = library-contract`
- `SSH_SERVER_LIBRARY`
  - `status = LIBRARY_CONTRACT`
  - `publicPath = library-contract`

## Error Model

### Family

当前 provider family 建议最少使用：

- `BAD_INPUT`
- `VERIFY_FAILED`
- `KEY_NOT_FOUND`
- `CRYPTO_UNAVAILABLE`
- `COMPLIANCE_REJECTED`
- `UNSUPPORTED`
- `INTERNAL_ERROR`
- `TLS_PRECHECK_ERROR`
- `TLS_HANDSHAKE_ERROR`
- `TLS_VERIFY_ERROR`
- `PROVIDER_UNAVAILABLE`

### Phase

当前 provider phase 建议使用：

- `PROVIDER_SELECTION`
- `TLS_PRECHECK`
- `TLS_HANDSHAKE`
- `TLS_VERIFY`
- `PROVIDER_RUNTIME`

### Mapping Intent

- `VERIFY_FAILED + TLS_PRECHECK` -> `TLS_PRECHECK_ERROR`
- `VERIFY_FAILED + TLS_HANDSHAKE` -> `TLS_HANDSHAKE_ERROR`
- `VERIFY_FAILED + TLS_VERIFY` -> `TLS_VERIFY_ERROR`
- `CRYPTO_UNAVAILABLE + PROVIDER_SELECTION / PROVIDER_RUNTIME` -> `PROVIDER_UNAVAILABLE`
- 其余错误优先保持原始 family，而不是全部压成一段 message

## Fallback Recommendation

`contractRecommendProviderFallback(...)` 当前建议：

- `PROVIDER_UNAVAILABLE` / `CRYPTO_UNAVAILABLE` / `UNSUPPORTED`
  - 建议回退到 `stdx`
- `TLS_HANDSHAKE_ERROR`
  - 可谨慎重试，或回退到 `stdx`
- `BAD_INPUT` / `COMPLIANCE_REJECTED` / `TLS_PRECHECK_ERROR` / `TLS_VERIFY_ERROR`
  - 不建议自动回退，应直接上抛

如果上层还需要把这些建议进一步收成试运行 / 观测口径，当前推荐直接消费：

- `contractDescribeProviderFallbackOutcomeGuide(...)`
- `contractListProviderFallbackOutcomeGuides()`
- `contractResolveProviderFallbackOutcome(...)`

当前固定 outcome 口径：

- `suggested-only`
  - 允许建议回到 `stdx-default`
  - 但不代表已经自动切换成功
- `no-auto-fallback`
  - 必须保留错误语义，不允许静默降级
- `no-fallback`
  - 当前已经在稳定默认路径上，没有第二条自动降级链
- `manual-review`
  - 当前路径已消耗连接，或已在稳定默认路径上且仍无可行自动降级，应交给上层重试/人工判定

当前推荐重点观察的 cause code：

- `provider_unavailable`
- `tls_handshake_error`
- `tls_verify_error`
- `tls_precheck_error`
- `tls_not_configured`
- `crypto_unavailable`

## Smoke Fixture Coverage

当前公开仓库现在通过 `contractProviderSmokeFixtureCatalog()` / `contractRequireProviderSmokeFixture(...)`
直接暴露一组稳定的 smoke / fault-baseline 元数据，供 provider 选择层消费。

当前固定 catalog：

- `success-x509-policy-chain`
  - category: `SUCCESS`
  - artifacts:
    - `testdata/x509/policy_root.pem`
    - `testdata/x509/policy_intermediate.pem`
    - `testdata/x509/policy_leaf.pem`
    - `testdata/x509/policy_leaf_key_pkcs8.pem`
- `precheck-cert-key-mismatch`
  - category: `PRECHECK_FAIL`
  - expected phase / family: `TLS_PRECHECK` / `TLS_PRECHECK_ERROR`
- `verify-hostname-mismatch`
  - category: `VERIFY_FAIL`
  - expected phase / family: `TLS_VERIFY` / `TLS_VERIFY_ERROR`
- `verify-pin-mismatch`
  - category: `VERIFY_FAIL`
  - expected phase / family: `TLS_VERIFY` / `TLS_VERIFY_ERROR`
- `verify-untrusted-chain`
  - category: `VERIFY_FAIL`
  - expected phase / family: `TLS_VERIFY` / `TLS_VERIFY_ERROR`
- `handshake-server-hello-decode`
  - category: `HANDSHAKE_FAIL`
  - expected phase / family: `TLS_HANDSHAKE` / `TLS_HANDSHAKE_ERROR`
- `attach-stable-listener-unpublished`
  - category: `HANDSHAKE_FAIL`
  - expected phase / family: `PROVIDER_RUNTIME` / `UNSUPPORTED`
- `provider-not-linked`
  - category: `PROVIDER_UNAVAILABLE`
  - expected phase / family: `PROVIDER_SELECTION` / `PROVIDER_UNAVAILABLE`
- `provider-experimental-gated-off`
  - category: `PROVIDER_UNAVAILABLE`
  - expected phase / family: `PROVIDER_SELECTION` / `PROVIDER_UNAVAILABLE`

建议上层至少区分：

- `precheck fail`
- `handshake fail`
- `verify fail`
- `provider unavailable`

如果上层要把 smoke suite 做成固定配置，而不是硬编码测试路径，建议：

- 通过 `fixtureId` 选定 smoke baseline
- 通过 `expectedPhase` / `expectedFamily` 统一错误桶
- 通过 `entrypoints` 决定调用哪一层 facade，而不是深挖 `crypto.*`

## Smoke Baseline Report

现在推荐 provider 选择层直接使用：

- `contractDescribeProviderSmokeBaseline(...)`
- `contractDescribeProviderSmokeBaselineRequest(...)`
- `contractTryDescribeProviderSmokeBaselineRequest(...)`

report 会把下面几层统一组装好：

- `fixture`：原始 smoke fixture metadata
- `executionMode`
  - `PRECHECK_PATH`
  - `VERIFY_PATH`
  - `PROVIDER_SELECTION_PATH`
  - `METADATA_ONLY`
- `expectedDescriptor`
- `expectedFallback`
- `capability`
- `attachBoundary`
- `warnings`

当前设计意图：

- 上层不必重复调用 `contractDescribeProviderErrorCode(...)` / `contractRecommendProviderFallback(...)`
- 上层可以直接按 `executionMode` 决定 smoke suite 应跑 precheck、verify、provider-selection，还是仅做 metadata assertion
- 当前 `HANDSHAKE_FAIL` baseline 会固定走 `METADATA_ONLY`，因为公开仓库尚未承诺稳定的 server-side attach / live provider handshake 入口

## Smoke Suite Report

如果上层不想逐个 fixture 查询，也可以直接用：

- `contractDescribeProviderSmokeSuite()`
- `contractDescribeProviderSmokeSuiteRequest(...)`
- `contractTryDescribeProviderSmokeSuiteRequest(...)`

suite report 会额外聚合：

- `baselines`
- `totalFixtureCount`
- `successFixtureCount`
- `failureFixtureCount`
- `precheckPathCount`
- `verifyPathCount`
- `providerSelectionPathCount`
- `metadataOnlyCount`
- `recommendedOrder`

这适合 provider 选择层在启动时拿一份“当前公开 smoke 计划总览”，再决定：

- 哪些项在 CI 中跑真实 precheck / verify
- 哪些项只做 metadata assertion
- 哪些项属于 provider-unavailable 预期路径，不应误报成运行故障

## Smoke Self-Check

如果上层希望把 smoke suite 再进一步收敛成一个“是否满足 provider 接入门槛”的 readiness 结论，可直接使用：

- `contractProviderSmokeSelfCheck(...)`
- `contractRequireProviderSmokeSelfCheck(...)`
- `contractTryProviderSmokeSelfCheck(...)`
- `contractTryRequireProviderSmokeSelfCheck(...)`

默认 policy 会要求：

- `client TLS`
- `X.509 verify`
- `TLS precheck`
- 至少一个 success baseline
- precheck / verify / provider-selection / handshake coverage
- 所有失败 baseline 都给出 fallback decision

默认 policy **不会**要求：

- stable server-side attach
- default HTTPS eligible
- live handshake coverage

这样做的原因是当前公开边界仍然是 `PRECHECK_ONLY`。因此默认 self-check 可以在“provider-candidate 可接入”层级返回 `overallReady = true`，同时通过 `warnings` 明确提示：

- 当前 release line 仍是 experimental / provider-candidate
- stable server attach 尚未发布
- handshake coverage 目前仍是 metadata-only

如果上层想收紧门槛，例如要求 stable attach 或 live handshake coverage，可以在 policy 中显式打开对应项；这时 `contractRequireProviderSmokeSelfCheck(...)` 会以 `UNSUPPORTED` 失败返回，便于 provider selector 或 CI gate 直接阻断。

## Smoke Profiles

如果上层不想直接自己组装 policy，而是希望拿“命名好的门槛模板”，可以直接使用：

- `contractDescribeProviderSmokeProfile(...)`
- `contractListProviderSmokeProfiles()`
- `contractRequireProviderSmokeProfile(...)`
- `contractTryRequireProviderSmokeProfile(...)`

当前公开 profile：

- `provider-candidate`
  - 对应当前 release line 的默认门槛
  - 接受 `PRECHECK_ONLY` 与 metadata-only handshake coverage
- `attach-planning`
  - 适用于仍处于 attach 规划期的上层
  - 不要求 provider-selection / handshake coverage，但保留 fallback discipline
- `default-https-eligible`
  - 面向“是否能升级成默认 HTTPS 路径”的门槛
  - 需要 stable attach 与 default eligibility
- `live-attach-experimental`
  - 面向实验性 live attach 验证
  - 需要 stable attach 与 live handshake coverage
- `production-strict`
  - 最严格 profile
  - 同时要求 stable attach、default eligibility、live handshake coverage

这样 provider selector / CI gate 可以直接固定 profile 名称，而不用把一大串 policy bool 散落在业务仓里。

## Non-Goals

当前这份 contract 不承诺：

- 直接替代默认 HTTPS listener
- 在 Ignite 主线暴露 provider backend 细节
- 让应用层自己承担 provider fallback 决策
