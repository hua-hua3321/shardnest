# 安全模型

## 架构分层（薄壳模型）

```
MCP server（无密钥）→ 本地 IPC → 签名守护进程（唯一持钥者）
```

- MCP 层被攻破：拿不到任何密钥
- 签名守护进程：Keychain/Keystore 保护 + OS 弹窗确认 + 私钥用完清零

## 密钥生命周期

| 阶段 | 位置 | 保护 |
|------|------|------|
| 生成 | 客户端（CSPRNG） | 私钥不参与任何口令/身份因子 |
| 分片 | SSS 2-of-3 | 单分片零信息量 |
| 存储 | 设备 Keychain + 用户云盘/恢复码 | 口令仅加密分片（KEK），非私钥 |
| 签名 | 内存实时重组 | 用完清零 |
| 轮换 | reshare | ⚠️ 必须物理清理旧载体（旧分片集内部仍可重组） |

## 威胁矩阵

| 威胁 | 防护 | 残余风险 |
|------|------|---------|
| 服务方被黑 | 零密钥材料 | 无 |
| 用户设备被控 | Keychain + 弹窗 | 设备完全沦陷无法防御（同硬件钱包） |
| prompt injection | 平台背书 + 用户确认 | 用户误点（高价值操作二次口令） |
| 单分片泄露 | 2-of-3 门限 | 需 2 片同时泄露 |
| 助记词文件泄露 | 仅本地 0600 文件；用户生成时已被告知单点风险 | **泄露即资金丢失（无门限保护）**；建议抄写离线保存后执行 `wipe saved` 删除本机明文 |
| 助记词+恢复码同机 | 各自独立保管责任 | 多重独立泄露面叠加；生成助记词后建议立即离线转移并 wipe |
| 口令+设备双丢 | — | 不可恢复（注册时披露，合理边界） |
| **LLM 会话泄露口令/恢复码** | **解锁令牌机制**：口令/恢复码只在本地 CLI 输入，MCP 只接收 5min 单次令牌（0600 加密落盘、消费即删） | 令牌泄露窗口=5min+单次，且仍需平台背书+用户确认 |

## 安全修复记录

### 2026-08-10 专家审查修复（加密货币 × 安全双视角）

| 级别 | 问题 | 修复 |
|------|------|------|
| 🔴 P0 | MCP 工具参数暴露口令/恢复码给 LLM | 解锁令牌机制（`unlock-session.ts`）：CLI `unlock` 本地输入口令+恢复码 → 组合私钥 → 令牌加密落盘（5min TTL/0600/单次）；MCP `signed_request_sign` 只接收 `unlock_token`，签名后令牌即删 |
| 🟠 P1 | 恢复码无校验 → 输错静默恢复错误钱包 | 恢复码格式 `sn1-<index>-<hex>-<crc>`（keccak 首字节）；`restore` 地址交叉校验（expectedAddress/旧 metadata） |
| 🟠 P1 | init/restore 非原子 | init 先发邮件后落盘；restore 写入失败回滚 meta |
| 🟠 P1 | 签名不校验 wallet_address | `signed_request_sign` 强制本地地址一致 → `WALLET_ADDRESS_MISMATCH` |
| 🟡 P2 | 弱口令 / canonical 分隔符歧义 / 坏私钥静默 / 输入回显 | 口令 ≥12 位强制；canonicalString JSON 序列化；`WalletVault` 私钥范围校验（0<priv<n）；CLI 掩码输入 |

> 全量 61/61 测试全绿（含新增：CRC 篡改、地址不匹配、无效令牌、口令强度）。

### 2026-08-10 深入审查修复（三视角并行：完整性 × 正确性 × 影响面）

| 级别 | 问题 | 修复 |
|------|------|------|
| 🔴 Critical | `wallet_restore` 绕过凭证隔离：恢复码×2 入参 + 明文出参全进 LLM | 输入改本地文件读取（`recovery_file_path`）；输出改 `recovery_codes_file`+`note`；min(12)；新增 expected_address/email 参数与 2 条功能测试 |
| 🟠 Warning | `signMessage`/`createUnlockToken` 异常路径私钥残留 | `vault.wipe()` 移入 finally；privateKey null 初始化 + finally 清零 |
| 🟠 Warning | init/restore 恢复码落盘不在原子/回滚范围 | 落盘前置（失败不再产生锁死态）；meta/device/recovery 三文件统一回滚 |
| 🟠 Warning | 地址交叉校验新设备场景失效 / 邮箱更新指引不可执行 | CLI/MCP 暴露 `expected_address`；`restoreWallet` 新增 email 参数自动发送新片③ |
| 🟡 Suggestion | CLI 恢复码回显 / user_id·action 无校验 / 裸 0x19 / schema 0x 漂移 | 掩码输入；action 白名单+user_id 校验；`\x19` 转义；schema 去 0x |
| 🔴 **口令令牌** | **`wallet_create`/`wallet_restore` 口令参数仍进 LLM（最后残余凭证）** | **`passphrase_token` 机制**：CLI `passphrase-token` 本地输入口令 → 生成口令会话令牌（`passphrase-*` 文件，5min/0600/单次）；MCP 工具只接收令牌，口令明文永不经 LLM——**口令+恢复码全部凭证闭环** |

> 全量 72/72 测试全绿。

## 依赖审计要求

- 密码学依赖：noble-curves / noble-hashes（审计级、纯 TS、零依赖）
- SSS：自研 GF(256) 实现 + 向量测试（tests/）
- 任何新增密码学依赖必须附审计/来源说明
