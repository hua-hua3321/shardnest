# shardnest 钱包服务 · 长期项目记忆

## 安全加固范围决策（2026-08-12）
- 用户明确：**P2 项与 P0-3（独立签名守护进程）暂不实装**，除非后续主动要求。
- 已完成的安全加固（用户认可范围）：依赖 OSV 扫描（0 CVE）、P0-1（MCP isError）、P1-7（passphrase purpose）、P1-#2（display 签名，经核实已落地）、P1-#3（nonce 重放兜底 ReplayGuard）、P1-#4（口令熵下限 + scrypt N=2^18）。P0-3 仅完成设计文档 `docs/DES-017-isolated-signing-daemon.md`，未落地实现。
- 审查报告 `SECURITY-REVIEW-2026-08-12.md` 相对当前代码**多次过时**（isError/purpose/display/口令基础校验均已前置应用）——后续若再审计，务必先读源码核对，勿直接采信报告中的"未修复"结论。

## 测试/构建约定
- 全量测试：`bun run test`（= 各包 `bun test`）；类型检查 `bunx tsc --noEmit`；构建 `bun run build`。
- 改任意包源码后需 `bun run build`（mcp-server 经 dist 引用 signer/cli/core 等）。
- 测试隔离：`SHARDNEST_HOME` 指向临时目录（如 `.test-shardnest-*`）。
