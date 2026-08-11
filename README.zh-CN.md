# shardnest

**自托管、非托管的钱包基础设施**——密钥生成、Shamir 秘密共享（2-of-3）、签名、恢复全部在用户本机完成，平台零密钥材料。任何符合 `signed_request` v1 协议的平台均可接入。

> English version: [README.md](README.md)

## 为什么选择 shardnest

- **平台零密钥材料** — 私钥的生成、分片、签名 100% 在用户本地环境完成；平台只存储公开的钱包地址，不接触、不存储、不托管任何私钥。
- **可恢复** — 2-of-3 SSS 分片：设备丢失、口令遗忘、丢一个恢复码，都不会丢钱包。
- **LLM 安全凭证隔离** — 口令与恢复码永不进入 LLM 上下文。CLI 本地生成单次使用令牌（5 分钟 TTL、0600 权限、原子消费）；MCP 工具只接收令牌或本地文件路径。
- **开放协议** — 通过 `signed_request` v1（平台背书签名请求）接入，任何平台皆可集成，无锁定。

## 快速开始

环境要求：[Bun](https://bun.sh) ≥ 1.3。

```bash
bun install

# 创建钱包（交互式，口令掩码输入）
SHARDNEST_HOME=$(mktemp -d) bun packages/cli/src/index.ts init

# 命令
bun packages/cli/src/index.ts address                      # 显示地址（无需秘密）
bun packages/cli/src/index.ts passphrase-token             # 本地口令 → 单次口令令牌
bun packages/cli/src/index.ts unlock                       # 本地解锁 → 签名令牌
bun packages/cli/src/index.ts sign "<消息>"                 # EIP-191 个人消息签名
bun packages/cli/src/index.ts restore                      # 用 2 个恢复码恢复钱包
```

`~/.shardnest/` 目录（可用 `SHARDNEST_HOME` 覆盖）：

```
metadata.json        明文 { address }——地址非秘密
device-share.json    片①，口令加密（scrypt KEK + AES-GCM，0600）
recovery-codes.txt   片②（+片③，仅邮箱未送达时）明文恢复码（0600，用户自持责任）
unlock/              令牌会话：unlock-*.bin / passphrase-*.bin / consuming-*.bin
mnemonic.txt          （可选）24 词助记词 = 完整私钥备份（单点，0600）
```

## 密钥管理模型

- **创建**：CSPRNG 生成私钥 → SSS 2-of-3 分片 → 片①口令加密存设备，恢复码②+③写入本地文件；可选通过 SMTP 将片③同时发送到邮箱（单片零信息量）。
- **签名**：平台用自持私钥签发 `signed_request` 背书 → MCP 验背书、校验 `wallet_address`、用户确认（双闸门）→ 消费本地解锁令牌 → 内存签名 → 清零。
- **恢复**：任意 2 片重组同一私钥。`restore` 会用派生地址与期望地址/旧 metadata 交叉校验，拒绝输错的恢复码。

## CLI 命令参考

所有命令均为交互式（口令与恢复码掩码输入）。

| 命令 | 用途 | 关键交互 / 输出 |
|------|------|----------------|
| `init` | 创建钱包 | 掩码口令 → 邮箱（可选，发送片③）→ 是否生成 24 词助记词（默认否）→ 打印恢复码，落盘 `~/.shardnest/` |
| `address` | 显示地址 | 无（无需秘密） |
| `passphrase-token` | 生成口令令牌（MCP 创建/恢复用） | 掩码口令 → 输出令牌（5 分钟/单次，勿在聊天中转发） |
| `unlock` | 生成解锁令牌（MCP 签名用） | 掩码口令 + 恢复码 → 输出令牌 |
| `sign <消息>` | EIP-191 个人签名 | 掩码口令 + 恢复码 → `{address, signature}` |
| `restore` | 用 2 个恢复码恢复 | 新掩码口令 → 2 个掩码恢复码 → 期望地址（可选，强烈建议）→ 邮箱（可选） |
| `restore-mnemonic` | 24 词助记词单独恢复 | 新掩码口令 → 24 词 → 期望地址（可选）→ 邮箱（可选） |
| `mnemonic-export` | 任意 2 片导出 24 词助记词 | 模式 a) 设备片+恢复码，或 b) 两个恢复码 → 写入 `mnemonic.txt` |
| `wipe` | 彻底删除（不可恢复） | 选择范围：1) 仅需保存的备份文件 2) 全部 → 文件清单 → 确认短语 `PERMANENT DELETE` |

### 助记词（可选，默认关闭）

- **仅支持 24 词**：12 词仅 128 位 < 256 位私钥（容量约束）。
- **shardnest 专用编码**（私钥直接作 BIP-39 熵，不走标准 seed→BIP-32 派生）——**不兼容 MetaMask / Ledger / Trust Wallet 等主流钱包**（导入会得到不同地址），仅限 shardnest 内部使用。
- 助记词 **= 完整私钥（单点）**——泄露即资金丢失，无门限保护。请离线保管（纸/密码管理器），随后执行 `wipe`（范围 1）删除本机明文副本。
- `init` 时可选生成，或随时用 `mnemonic-export`（任意 2 片）导出；用 `restore-mnemonic` 恢复。

### 邮箱备份（可选）

| 环境变量 | 说明 |
|---------|------|
| `SHARDNEST_SMTP_HOST` | SMTP 服务器（配置后启用） |
| `SHARDNEST_SMTP_PORT` / `TLS` | 默认 465 / true |
| `SHARDNEST_SMTP_USER` / `PASS` / `FROM` | 凭据 / 发件人（默认 USER） |

恢复码完整性：32 位 CRC（keccak256 前 4 字节）——错误漏检率 1/2^32。

创建后的备份分布：
- **邮箱已送达** → 本地 `recovery-codes.txt` 仅存片②（片③在邮箱）——本机整体泄露无法动钱。
- **未配邮箱** → 片②③均在本机本地文件（显著警告）；建议转移 1 片离线保存或配置邮箱。

### wipe — 两种范围

| 范围 | 删除内容 | 删除后钱包 |
|------|---------|-----------|
| 1) 仅需保存的备份（默认/推荐） | 恢复码 + 助记词（明文备份） | 仍可用（口令解锁） |
| 2) 全部 | 设备片 + 备份 + metadata + 令牌会话 | 需用保存的恢复码/助记词重建 |

两种范围均先随机覆写 3 遍再删除（不可恢复），且需输入确认短语 `PERMANENT DELETE`。

## MCP 工具

启动服务：

```bash
SHARDNEST_PLATFORM_ADDRESS=<平台背书地址> SHARDNEST_HOME=~/.shardnest \
bun packages/mcp-server/src/index.ts
```

敏感凭证永不作工具参数——经本地令牌文件/文件路径通道（与 LLM 隔离）。

| 工具 | 参数 | 说明 |
|------|------|------|
| `wallet_create` | `passphrase_token`、`email?`、`generate_mnemonic?` | 返回 `recovery_codes_file` / `mnemonic_file` 路径（明文不进 LLM）；**钱包已存在时拒绝**（`WALLET_EXISTS`，不消费令牌）——重建需先 `wallet_wipe`（宿主 approval 确认）或 CLI `init` 交互确认 |
| `wallet_address` | — | 当前地址 |
| `wallet_mnemonic_export` | — | 需确认闸门；24 词助记词写入本地文件，仅返回路径 |
| `signed_request_sign` | `signed_request`、`unlock_token` | 双闸门（平台背书 + 用户确认）；签 `action:intent_hash` |
| `wallet_restore` | `recovery_file_path?` / `mnemonic_file_path?`、`passphrase_token`、`expected_address?`、`email?` | 文件路径必须在钱包目录内 |
| `wallet_wipe` | `scope?`（默认 `saved` / `all`） | 需确认闸门；返回删除文件清单 |

## 业务平台接入（任意平台）

1. **签发**：平台用自持私钥签发 `signed_request`（`@wallet-service/protocol` 的 `issueSignedRequest`）。
2. **签名**：用户 Agent 调用 MCP `signed_request_sign`——验背书、校验 `wallet_address`、用户确认、消费本地令牌、返回 EIP-191 签名。
3. **验签**：平台用 `@wallet-service/verify-sdk` 的 `recoverSigner(message, sig)` 还原地址，必须与绑定的 `wallet_address` 一致。

`signed_request` v1 规范与 JSON Schema 见 [protocol/README.md](protocol/README.md)。

## 架构

```
core（纯密码学，无 IO）     GF(2^8) SSS · keccak 地址 · EIP-55 · scrypt KEK
signer                      WalletVault（唯一持钥者）· 确认闸门 · 令牌会话
cli                         命令实现 · 恢复码 CRC · SMTP 备份
verify-sdk                  平台侧 EIP-191 验签（verify-only，零密钥）
protocol                    signed_request v1——平台背书签发/验签
mcp-server                  无密钥薄壳，接线双闸门
```

密码学不变式见 [AGENTS.md](AGENTS.md)——改动密码学代码前务必阅读（GF(2^8) 生成元必须为 3、EIP-191 哈希三处字节级一致、恢复码 CRC 覆盖 `index:hex`、所有路径内存清零）。

## 测试

```bash
cd packages/<pkg> && bun test          # 单包
for p in core signer cli verify-sdk protocol mcp-server; do (cd packages/$p && bun test); done
```

## 文档

- [安全模型](docs/SECURITY.md) — 威胁矩阵、密钥生命周期、修复记录
- [设计（DES-016）](docs/DES-016-self-custodial-wallet-service.md) — 完整设计与路线图
- [协议](protocol/README.md) — `signed_request` v1 规范与 JSON Schema

## 许可证

MIT
