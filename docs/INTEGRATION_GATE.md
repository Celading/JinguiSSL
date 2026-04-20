# jinguiSSL Integration Gate

## Goal

确保 HTTP / SSH 集成方在接入 `jinguiSSL` 时，优先通过稳定 facade 完成校验、握手输入预检查与错误统一映射。

## Naming Contract

- 品牌名：`jinguiSSL`
- `cjpm` 依赖名：`jinguissl`
- 稳定 import：
  - `jinguissl.contract.*`
- 当前构建产物前缀：
  - `libjinguissl*.a`

集成侧如果把品牌名 `jinguiSSL` 直接当作链接名使用，例如 `-ljinguiSSL.contract`，将无法命中实际产物。

当前公开仓库默认只把 `jinguissl.contract.*` 视为稳定依赖面；本地实验性 bridge 不属于当前公开契约。

## Current Gate

- `P0-1`：主库在当前主开发平台可 `cjpm build`
- `P0-2`：公开的 contract facade 能力测试持续通过
- `P0-3`：失败路径与错误码可观测
- `P0-4`：HTTP TLS 配置输入可先经 contract precheck 再进入外部 TLS 配置构造
- `P0-5`：公开库能力已具备作为 HTTP / SSH 集成核心的最小闭环
- `P0-6`：打包阶段可通过仓库内补完脚本产出可校验 `.cjp`

## Recommended Pattern

1. 上层先调用 contract facade 做证书、私钥、协商参数与策略预检查
2. 通过 precheck 后，再进入各自框架或运行时的 TLS / SSH 配置构造
3. 统一使用 contract 返回面做错误分流，而不是自行解析底层异常

若你要自己实现 TLS / SSH 的接口握手层，而不是只消费 gate 结论，继续看：

- `HANDSHAKE_INTERFACE_GUIDE.md`
- `examples/handshake-interface-demo/`
- `examples/http-client-consumption-smoke/`
- `examples/ssh-library-consumption-smoke/`

## HTTP Client First Flight

对 HTTP client TLS 首包，当前 contract 边界固定为：

- `contractTls13BuildHttpClientHelloX25519(...)` 返回的是 `ClientHello` 握手报文；
- 若上层要直接写 socket，应先调用
  `contractTlsEncodePlaintextRecord(ContractTlsVersion.Tls12, ContractTlsRecordContentType.Handshake, ...)`
  把握手报文封装成首条 TLS record；
- 这一步只解决 client first-flight 的 wire packaging，不表示本仓已经公开稳定的 server attach 入口。
- 完整最小路径见：
  - `HANDSHAKE_INTERFACE_GUIDE.md`
  - `examples/handshake-interface-demo/`
  - `examples/http-client-consumption-smoke/`（聚焦 `HTTP_CLIENT_TLS` 的 gate / fallback / verified-session smoke）

## Provider Gate

面向 `lisi` / provider 选择层，当前推荐直接消费下面这些稳定 contract：

- `contractProviderCapabilityRecord()`
- `contractProviderAttachContractInfo()`
- `contractProviderServerAttachBoundary()`
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

当前 server attach 结论固定为：

- `jinguissl` 在本仓公开范围内只保证 `precheck + material preparation`
- 不保证稳定的 server-side TLS attach 入口
- 若上层需要真实监听链 attach，应由 `lisi` 负责 provider 选择、fallback 与记录
- 在现阶段，`jinguissl` 不能被表述为默认 HTTPS listener 路径

当前路径级消费建议固定为：

- HTTP client TLS：
  - 可尝试 `jinguissl`
  - 仍是 provider-candidate，不等于默认切换
- HTTP server attach planning：
  - 只允许停在 `precheck + material preparation + planning`
  - 不允许包装成稳定 listener attach
  - focused example:
    - `examples/http-server-attach-planning-smoke/`
- SSH client/server：
  - 作为稳定库面直接消费 `jinguissl.contract.*`
  - 不依赖 `stdx.net.tls.TlsServerConfig` attach bridge
  - focused example:
    - `examples/ssh-library-consumption-smoke/`

若上层不想自己再把 path guide、smoke profile、readiness 与 fallback target 拼装成一层 release gate，当前也可直接消费：

- `contractDescribeProviderConsumptionGate(...)`
- `contractListProviderConsumptionGates()`
- `contractRequireProviderConsumptionGate(...)`
- `contractTryRequireProviderConsumptionGate(...)`

当前 gate status 解释固定为：

- `PROVIDER_CANDIDATE`
  - 当前可尝试 `jinguissl`，但仍保留 `stdx-default` 作为稳定 fallback target
- `PLANNING_ONLY`
  - 当前只允许 `precheck + material preparation + attach planning`
- `LIBRARY_CONTRACT`
  - 当前是稳定库面消费，不属于 provider attach 问题
- `BLOCKED`
  - 当前不是公开稳定路径，应该 fail closed

当前 gate report 还会补齐一组更贴近 `lisi` / observe 字段的摘要：

- `providerId`
  - 当前固定为 `jinguissl`
- `selectedEntryId`
  - `readyNow = true` 时可直接用于上层 `selectedBackend` / provider-entry 记录
  - `readyNow = false` 时固定为空字符串，避免伪造“已选中”
- `candidateOrder`
  - 当前按 `jinguissl` provider entry 在前、稳定 fallback entry 在后输出
- `blockedCandidates`
  - 当前在 blocked / smoke-not-ready 路径上给出结构化 blocked 原因
- `releasePath`
  - `experimental-only`
  - `library-direct`
  - `unsupported`
- `riskLevel`
  - `medium`
  - `low`
  - `high`
- `fallbackChain`
  - 当前主要用于表达 `stdx-default` 是否仍是建议回退链
- `observabilityTags`
  - 当前会固定补齐 `provider_id`、`provider_entry`、`selected_entry`、`public_path`、`release_path`、`risk_level`、`ready_now` 等标签

## Fallback Guidance

推荐由 `lisi` 执行并记录 fallback，`jinguissl` 侧给出如下边界建议：

- `PROVIDER_UNAVAILABLE` / `CRYPTO_UNAVAILABLE` / `UNSUPPORTED`
  - 允许回退到 `stdx`
- `TLS_HANDSHAKE_ERROR`
  - 可谨慎重试，或回退到 `stdx`
- `BAD_INPUT` / `COMPLIANCE_REJECTED` / `TLS_PRECHECK_ERROR` / `TLS_VERIFY_ERROR`
  - 不建议自动回退，应直接上抛并保留失败记录

若上层需要统一落到观测或 trial-build 口径，建议按下列 outcome 理解：

- `suggested-only`
  - 可以建议回退到 `stdx-default`
- `no-auto-fallback`
  - 不允许静默降级
- `no-fallback`
  - 当前已经处于稳定默认路径，没有下一条自动回退链
- `manual-review`
  - 当前需要上层重试/人工判定，不应继续自动切换

## Packaging Gate

当前工具链下，原生 `cjpm bundle` 仍可能在已生成有效产物后，因 SHA256 相关索引阶段崩溃退出。

推荐发布路径：

```bash
./tools/release_guard.sh
```

若需要分步观察 bundle 行为，也可以执行：

```bash
./tools/cjpm_bundle_finish.sh
./tools/cjpm_bundle_audit.sh
```

发布前至少检查：

1. `./tools/release_guard.sh`

或按分步链路执行：

1. `cjpm build`
2. `cjpm test --no-progress`
3. `./tools/cjpm_bundle_finish.sh`
4. `./tools/cjpm_bundle_audit.sh`

若 `release_guard.sh` 通过，说明当前仓库已经按推荐顺序完成 build / test / bundle / audit 全链路门禁。

若分步链路中的第 3 步成功，说明当前仓库可产出有效 `.cjp`，即使原生命令退出码仍受上游工具链 bug 影响。

若 `release_guard.sh` 通过，或分步链路中的第 4 步成功，说明：

- `.cjp` 制品可读；
- `.sha256` 与实际产物一致；
- bundle manifest 与制品、日志、已知上游崩溃语义保持一致。

## Public Constraint

- 当前公开仓库提供的是**库能力与 facade**
- HTTP 服务框架接线、动态 bridge、私有集成脚本不在本次公开范围
- `_helper/` 内的上下文备份、issue 留痕、参考仓库与本机路径文档不属于公开 API 文档
