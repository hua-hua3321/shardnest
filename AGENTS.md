# AGENTS.md

This file provides guidance to Lingma (lingma.aliyun.com) when working with code in this repository.

## 项目概览

**shardnest（钱包服务）**——开源、自托管、非托管的钱包基础设施。用户本地部署 MCP server 管理密钥，平台零密钥材料。钱包密钥生成、Shamir 2-of-3 分片、签名、恢复全部在用户本地完成；任何符合 signed_request v1 协议的平台均可接入。完整设计见 `docs/DES-016-self-custodial-wallet-service.md`，安全模型见 `docs/SECURITY.md`。

## 常用命令

```bash
# 安装依赖（workspace，改动任意 package.json 后必须执行）
bun install

# 单包测试（开发主循环）
cd packages/<pkg> && bun test

# 单个测试文件 / 单个用例
cd packages/<pkg> && bun test ./test/commands.test.ts
cd packages/<pkg> && bun test -t "用例名关键词"

# 全量测试（6 包：core signer cli verify-sdk protocol mcp-server）
for p in core signer cli verify-sdk protocol mcp-server; do (cd packages/$p && bun test); done

# 类型检查
bunx tsc --noEmit

# CLI 冒烟（临时目录隔离，不污染真实钱包）
SHARDNEST_HOME=$(mktemp -d) bun packages/cli/src/index.ts init
```

## 架构大图

### 包分层与依赖方向（严格单向）

```
core（纯密码学，无 IO）
  ├─ shamir.ts   GF(2^8) SSS（生成元 3 建表；split/combine/reshare）
  └─ keys.ts     CSPRNG 熵（根）、BIP-39/44 派生私钥、keccak 地址、EIP-55、scrypt KEK
  └─ mnemonic.ts 熵↔24 词标准编码（@scure/bip39）、seed、BIP-32 m/44'/60'/0'/0/0 派生
signvault.ts   WalletVault：注入已派生私钥→EIP-191 签名→wipe（O4A：组合/派生在命令层）n_message）
  └─ unlock-session.ts  令牌会话：unlock（私钥）/passphrase（口令）两型，
                         0600 加密落盘 + 5min TTL + rename 原子消费（单次）
cli（命令实现，MCP 的库 API 经 src/api.ts 的 exports 字段暴露）
  ├─ commands.ts  init/restore/sign/unlock/地址校验/恢复码 CRC（sn1-<idx>-<hex>-<crc>）
  ├─ mailer.ts    SMTP 备份分片（片③）发送（SHARDNEST_SMTP_* 环境变量）
  └─ index.ts     CLI 入口（掩码输入 promptSecret）
verify-sdk（平台侧验签，verify-only 零密钥）
protocol（signed_request v1：平台背书签发/钱包验签；canonicalBytes length-prefixed 二进制）
mcp-server（薄壳：凭证不进 LLM，6 工具 + 双闸门接线；独立无密钥进程为路线图 P0-3）
```

### 凭证隔离（本仓库最核心的安全架构，勿破坏）

**口令与恢复码永不经 LLM 上下文**。三条通道：

| 凭证 | 通道 | 机制 |
|------|------|------|
| 口令 | `passphrase_token` | CLI `passphrase-token` 本地输入 → `unlock/passphrase-*` 文件（0600/5min/单次）→ MCP 消费 |
| 恢复码输入 | `recovery_file_path` | 只传本地文件路径，内容由 MCP 进程从 `recovery-codes.txt` 读取 |
| 恢复码输出 | `recovery_codes_file` | MCP 响应只含文件路径 + 邮箱状态，绝不含明文 |

**铁律**：新增/修改 MCP 工具时，任何敏感凭证参数（口令、恢复码、私钥）必须改为令牌或文件路径通道；CLI 输入必须走 `promptSecret` 掩码。

### 关键密码学不变式（改动前必须理解）

1. **GF(256) 生成元必须是 3**（0x03）——元素 2 的乘法阶仅 51，非本原元，建表会漏元素
2. **EIP-191 哈希三处一致**：`vault.ts` / `verify-sdk/index.ts` / `protocol/signed-request.ts` 的 `personalMessageHash` 必须字节级一致，否则签名验签全面失配
3. **恢复码 CRC 覆盖 `index:hex`**——`decodeRecoveryCode` 校验 index ∈ [1,255] 整数 + hex 格式 + CRC；篡改任一字段即拒绝
4. **私钥范围校验**：`WalletVault.assertValidPrivateKey`（0 < priv < n）防组合出坏私钥静默签名
5. **敏感材料内存清零**：所有组合出的熵、私钥、BIP-39 seed 与明文分片用后必须 `fill(0)`（含异常路径，用 finally）——seed 敏感度等同私钥（可派生全部子私钥）
6. **原子性**：init/restore 的可失败操作（邮件/恢复码落盘）全部前置，最后才写 meta/device；失败三文件回滚
7. **reshare 语义**：旧分片集密码学上仍可重组同一私钥——reshare 后必须提示物理清理旧载体（恢复码文件/邮箱旧邮件）

### 存储布局（`~/.shardnest/`，测试用 `SHARDNEST_HOME` 隔离）

```
metadata.json       明文 { address }（地址非秘密）
device-share.json   片①，口令加密（scrypt KEK + AES-GCM，0600）
recovery-codes.txt  片②（+片③，仅邮箱未送达时）明文恢复码（0600，用户自持责任）
mnemonic.txt        （可选）24 词助记词 = 完整私钥备份（单点，0600）
unlock/             令牌会话：unlock-*.bin / passphrase-*.bin / consuming-*.bin

⚠️ 安全删除：wipe 双模式（saved=仅删明文备份，钱包保留 / all=全删），
覆写 3 遍 + 确认短语「PERMANENT DELETE」；MCP 文件路径参数必须位于钱包目录内。
```

### 签名流程（双闸门）

```
平台 issueSignedRequest（平台私钥背书）→ MCP signed_request_sign：
  闸门1 verifySignedRequest（背书验签 + nonce/expires_at/字段格式 + wallet_address 与本地一致）
  闸门2 approval 回调（宿主注入，默认仅放行 sign_message）
  → 消费 unlock_token → WalletVault 签名 → wipe
```

## 测试惯例

- 测试隔离：`SHARDNEST_HOME` 指向临时目录（如 `.test-shardnest-*`，已 gitignore）
- 密码学用已知向量（如私钥 0x01 → 地址 `0x7E5F...5Bdf`）；跨包闭环（签发→验签→验签还原）
- 覆盖负向路径：错误口令（GCM 认证失败）、篡改恢复码、过期/伪造背书、地址不匹配、无效令牌
- 新增工具/函数必须补测试；MCP 工具用 `InMemoryTransport` + `Client` 测试（handler 异常转 `isError: true`）
