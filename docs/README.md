# jinguiSSL Docs

本目录仅放置**公开文档**，用于说明当前仓库可对外承诺的能力、边界与集成方式。

## 阅读顺序

1. `API_BOUNDARY.md`
2. `CAPABILITY_MATRIX.md`
3. `PROVIDER_CONTRACT.md`
4. `INTEGRATION_GATE.md`
5. `HANDSHAKE_INTERFACE_GUIDE.md`
6. `PACKAGING_AUDIT.md`
7. `SSH_FACADE.md`

## 文档索引

- `API_BOUNDARY.md`
  - 说明当前稳定 facade 的边界与演进规则
- `CAPABILITY_MATRIX.md`
  - 汇总当前面向 HTTP / SSH 的库能力覆盖面
- `INTEGRATION_GATE.md`
  - 说明集成侧推荐依赖方式、命名约束、发布门禁与打包注意事项
- `PROVIDER_CONTRACT.md`
  - 汇总 provider capability、attach boundary、consumption gate、错误模型与 fallback 建议
- `HANDSHAKE_INTERFACE_GUIDE.md`
  - 说明别人如何基于 `jinguissl.contract.*` 自己实现 TLS first-flight 与 SSH library handshake 接口层
- `PACKAGING_AUDIT.md`
  - 说明 `tools/release_guard.sh` 与 `.cjp` / `.sha256` / manifest 的发布审计路径与检查项
- `SSH_FACADE.md`
  - 说明 SSH contract facade、host verification 策略与返回模型

## 公开文档约定

- 默认对外推荐 `import jinguissl.contract.*`
- 不把 `_helper/`、`bridges/`、`benchmarks/` 视为公开稳定契约的一部分
- 若工具链层面存在已知限制，会在文档中明确标注 workaround，而不是假装问题不存在
