# jinguiSSL

`jinguiSSL` 是一个纯仓颉实现的 SSL/TLS 与密码学库，当前以“先服务 HTTP / SSH 所需库能力”为主线推进，对齐 BoringSSL 风格的库能力建设，同时保持仓颉原生 API 优先。

当前公开稳定入口优先推荐：

```cangjie
import jinguissl.contract.*
```

英文版见 `README-EN.MD`，俄文版见 `README-RU.MD`。

## 当前状态

- 版本阶段：`0.6.21`
- 发布定位：`pre-1.0`
- 产物形态：`static` 仓颉库
- 公开集成面：`jinguissl.contract.*`
- 当前主线目标：优先补齐 HTTPS / SSH 所依赖的库能力，而不是应用层程序

这意味着当前仓库提供的是密码学原语、证书能力、TLS/SSH 相关 facade 与验证入口，不提供 HTTP 服务框架、SSH 客户端套件或隧道类应用。

## 能力概览

- 对称能力：AES-GCM、ChaCha20-Poly1305
- 摘要与派生：SHA-256 / SHA-384、HKDF
- 随机能力：CSPRNG 可用性探测与随机字节生成
- 非对称能力：RSA、ECDHE（P-256 / P-384）、X25519、ECDSA、Ed25519
- 证书能力：PEM / DER 解析、证书链校验、hostname 校验、pinning 简化接口
- TLS 能力：TLS 1.2 / TLS 1.3 基础握手、记录层、session ticket / cache、key update、exporter
- SSH 能力：X25519 KEX、host verification、host key fingerprint、transport protection 所需 contract facade

## 命名与导入

- 品牌名：`jinguiSSL`
- `cjpm` 包名：`jinguissl`
- import 根：`jinguissl.*`
- 推荐稳定依赖：

```cangjie
import jinguissl.contract.*
```

不建议业务层直接深度依赖 `jinguissl.crypto.*`，除非你明确接受后续内部实现继续演进。

## 仓库公开范围

- 公开源码：`src/`
- 公开测试：`src/jinguissl/tests/`
- 公开向量与夹具：`testdata/`
- 公开示例：`examples/phase1-demo/`、`examples/handshake-interface-demo/`
- 公开文档：`docs/`
- 公开打包辅助脚本：`tools/cjpm_bundle_finish.sh`
- 公开打包审计脚本：`tools/cjpm_bundle_audit.sh`

以下目录当前主要用于本地协作、参考资料或实验留痕，不属于公开发布契约的一部分：

- `_helper/`
- `bridges/`
- `benchmarks/`

## 构建与验证

```bash
cjpm build
cjpm test
```

当前 `cjpm build` 与 `cjpm test` 应串行执行，避免共享 `target/` 目录造成伪失败。

## 打包说明

当前仓颉工具链下，原生 `cjpm bundle` 仍可能在产物已生成后触发已知的 SHA256 校验阶段崩溃。因此仓库内提供了补完脚本：

```bash
./tools/cjpm_bundle_finish.sh
./tools/cjpm_bundle_audit.sh
```

该脚本会：

- `tools/cjpm_bundle_finish.sh` 会调用 `cjpm bundle`，识别“产物已生成但校验阶段崩溃”的已知工具链问题，并为有效 `.cjp` 产物补齐 `sha256` 与 manifest

审计脚本会：

- `tools/cjpm_bundle_audit.sh` 会校验 `.cjp` 是否可读且包含核心公开文件
- `tools/cjpm_bundle_audit.sh` 会校验 `.sha256` 与实际产物是否一致
- `tools/cjpm_bundle_audit.sh` 会校验 bundle manifest 是否与产物、日志和已知崩溃语义一致

## 文档导航

- 文档索引：`docs/README.md`
- API 边界：`docs/API_BOUNDARY.md`
- HTTP / SSH 能力矩阵：`docs/CAPABILITY_MATRIX.md`
- Provider 合同：`docs/PROVIDER_CONTRACT.md`
- SSH facade：`docs/SSH_FACADE.md`
- 集成门禁：`docs/INTEGRATION_GATE.md`
- 接口握手指南：`docs/HANDSHAKE_INTERFACE_GUIDE.md`
- 打包审计：`docs/PACKAGING_AUDIT.md`

## 版本说明

`0.6.21` 表示当前库能力已明显超出阶段 1 的基础骨架，但仍未进入 1.0 稳定承诺阶段。后续在 `0.x` 期间，`contract` facade 会尽量保持稳定，而 `crypto.*` 的内部实现仍可能继续调整。

## 许可证

`Apache-2.0`
