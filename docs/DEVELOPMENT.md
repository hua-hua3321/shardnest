---
title: shardnest 开发与修改指南
date: 2026-08-09
status: active
last_reviewed: 2026-08-09
tags: ['development', 'contribution', 'guide']
---

# 开发与修改指南（DEVELOPMENT）

> 本指南说明**如何修改本项目**：结构、约束、流程、常见修改场景。

---

## 工作区结构

```
packages/
├── core/         # 纯密码学：熵生成、SSS 分片（GF(2^8)）、BIP-39/44 派生、scrypt/AES-GCM
├── signer/       # 签名守护：WalletVault（注入已派生私钥→EIP-191 签名→wipe）、令牌会话
├── cli/          # CLI 形态（人类场景；i18n 中英）
├── mcp-server/   # MCP 薄壳（无密钥；6 工具；approval 闸门）
├── verify-sdk/   # 平台侧验签 SDK（仅验签）
└── protocol/     # signed_request v1 规范（canonicalBytes + JSON Schema）
docs/             # 安全模型/教程/修改说明/开发指南/接入指南（中英双份）
```

## 关键不变式（改动前必须理解——违反即破坏安全）

1. **GF(256) 生成元必须是 3**（0x03）——元素 2 的阶仅 51，非本原元
2. **EIP-191 哈希三处一致**：`vault.ts` / `verify-sdk` / `protocol` 的 `personalMessageHash` 字节级一致
3. **恢复码 CRC 覆盖 index:hex**（32 位）——index ∈ [1,255]、hex 格式、CRC 三重校验
4. **私钥范围校验**：0 < priv < n（`assertValidPrivateKey`）
5. **敏感材料内存清零**：熵、私钥、BIP-39 seed、明文分片用后必须 `fill(0)`（含异常路径，用 finally）
6. **原子性**：init/restore 可失败操作前置，失败三文件回滚（含恢复码/助记词）
7. **reshare 语义**：旧分片集密码学上仍可重组同一密钥——reshare 后必须提示物理清理旧载体
8. **凭证隔离**：口令/恢复码/助记词明文**永不进 LLM**——MCP 只用令牌/文件路径通道
9. **默认应安全**：不可逆/高危 MCP 操作（wipe/导出助记词）默认拒绝，需宿主 approval

## 常用修改场景

### 场景 1：改 scrypt 参数

```ts
// packages/core/src/keys.ts
export const SCRYPT_OPTS = { N: 2 ** 17, r: 8, p: 1, dkLen: 32 } as const
```

- 新钱包自动用新参数；**旧钱包用密文持久化的 kdf 参数解密，不受影响**（O1）
- 无 kdf 字段的 v1 钱包回退 `LEGACY_SCRYPT_OPTS_V1`（2^16）——**勿改此常量**

### 场景 2：新增 MCP 工具

1. 在 `packages/mcp-server/src/index.ts` 加 `server.tool(...)`
2. 敏感输入（口令/恢复码）必须走令牌或文件路径通道——**禁止明文参数**
3. 高危操作（不可逆/私钥相关）必须加 approval 闸门；`ApprovalRequest.action` 类型联合同步扩展
4. 输出不得含明文敏感数据（返回文件路径）
5. 补测试（mcp.test.ts）

### 场景 3：修改派生路径（慎重）

- `BIP44_PATH` 在 `packages/core/src/mnemonic.ts`
- **改路径 = 所有新钱包地址变化 = 与 MetaMask 不兼容**——W15 固化测试会失败
- 必须同步更新 W15 固化地址（先经 MetaMask/iancoleman 实测确认）

### 场景 4：改恢复码格式

- `encodeRecoveryCode`/`decodeRecoveryCode` 在 `packages/cli/src/commands.ts`
- 保持双宽兼容（旧格式仍可解码）或接受破坏性变更并同步文档
- 32 位 CRC 覆盖 index:hex——校验逻辑不可削弱

### 场景 5：改协议（signed_request）

- `canonicalBytes` 在 `packages/protocol/src/signed-request.ts`——**跨语言契约**，改动即破坏
- 版本协商：升 `v` 字段并保留旧版兼容，或接受 breaking 并显著公告
- 同步 `protocol/README.md` + `signed-request-v1.schema.json`

## 测试

```bash
# 全量测试（6 包）
for p in core signer cli verify-sdk protocol mcp-server; do (cd packages/$p && bun test); done

# 单包
cd packages/cli && bun test ./test/commands.test.ts
```

- 类型检查必须 0 错误：`bunx tsc --noEmit`
- 密码学变更必须补向量/夹具测试（参考 W15 地址固化、C1 v1 真实夹具）

## 提交规范

- 原子化提交：一个逻辑变更一个提交
- 提交信息：`feat|fix|docs|test: 简述` + 变更明细
- 改完跑全量测试 + tsc 再提交
- 推送：GitHub（hua-hua3321/shardnest），网络不稳时重试

## 发布流程

见 [CHANGELOG.md](CHANGELOG.md) 发布流程章节。
