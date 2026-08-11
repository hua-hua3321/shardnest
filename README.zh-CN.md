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

## MCP server

```bash
SHARDNEST_PLATFORM_ADDRESS=<平台背书地址> \
SHARDNEST_HOME=~/.shardnest \
bun packages/mcp-server/src/index.ts
```

工具：`wallet_create` · `wallet_address` · `signed_request_sign` · `wallet_restore`。
敏感凭证永不作工具参数——一律使用 `passphrase_token` / `recovery_file_path` / `recovery_codes_file`。

邮箱备份（可选）：`SHARDNEST_SMTP_HOST / PORT / USER / PASS / FROM / TLS`。

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
