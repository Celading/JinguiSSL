# Packaging Audit

`jinguiSSL` 当前在仓颉工具链下采用“统一门禁 + 底层两步法”完成发布制品验收：

1. `./tools/release_guard.sh`
2. `./tools/cjpm_bundle_finish.sh`
3. `./tools/cjpm_bundle_audit.sh`

`release_guard.sh` 是推荐入口，会顺序执行：

1. `cjpm build`
2. `cjpm test --no-progress`
3. `./tools/cjpm_bundle_finish.sh`
4. `./tools/cjpm_bundle_audit.sh`

若你只需要底层 bundle 处理，也可以单独运行后两步：

- `./tools/cjpm_bundle_finish.sh` 负责拿到有效 `.cjp`，并在已知 SHA256 崩溃场景下补齐 `.sha256` 与 manifest。
- `./tools/cjpm_bundle_audit.sh` 负责审计产物一致性，避免“产物看起来存在，但发布元数据不完整或不匹配”的伪成功。

额外说明：

- 若执行环境限制了 `std.unittest` 默认 transport 的本地 socket bind，`tools/cjpm_bundle_finish.sh` 现在会明确报出 `local unittest transport bind was denied`；
- 这种情况说明当前是执行环境限制，而不是已知的 SHA256 workaround 命中路径；
- 解除该限制后，再判断是否回到真正的 `cjpm bundle` SHA256 崩溃问题。

## 审计内容

`tools/cjpm_bundle_audit.sh` 默认检查当前工作树对应版本的：

- `target/<name>-<version>.cjp`
- `target/<name>-<version>.cjp.sha256`
- `target/bundle-logs/<name>-<version>.bundle-manifest.json`

脚本会校验：

- `.cjp` 可被 `tar -tf` 正常读取
- 根目录名与 `<name>-<version>/` 一致
- 核心公开文件存在：
  - `cjpm.toml`
  - `README.md`
  - `src/jinguissl/jinguissl.cj`
  - `src/jinguissl/contract/contract.cj`
  - `src/jinguissl/crypto/aes/aes.cj`
  - `src/jinguissl/crypto/tls/tls13.cj`
  - `src/jinguissl/crypto/ssh/ssh.cj`
- `.sha256` 与实际产物哈希一致
- manifest 中的 `package / version / artifact / sha256` 与实际一致
- 若 manifest 标记 `knownUpstreamShaCrash = true`，则日志中必须能看到对应的 `stdx.crypto.digest / SHA256 / Abort trap: 6` 等已知特征

## 推荐发布顺序

```bash
./tools/release_guard.sh
```

若需要分步执行，则仍按：

```bash
cjpm build
cjpm test --no-progress
./tools/cjpm_bundle_finish.sh
./tools/cjpm_bundle_audit.sh
```

只要 `release_guard.sh` 通过，或分步执行中的第 4 步通过，就说明当前工作树对应的发布制品、校验文件和 bundle manifest 已经自洽，可作为发布审计依据。

## 可选参数

脚本支持按顺序覆盖默认路径：

```bash
./tools/cjpm_bundle_audit.sh <artifact-path> <sha256-path> <manifest-path>
```

这适合在临时 worktree、历史产物或 CI 缓存目录中做二次审计。
