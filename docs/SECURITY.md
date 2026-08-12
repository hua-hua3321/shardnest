# 安全模型

## 架构分层（薄壳模型）

> ⚠️ **当前实现状态**：下述「目标架构」（独立签名守护进程 + IPC + Keychain + OS 弹窗）
> 是**路线图目标，尚未实现**（P0-3）。当前 MCP server 直接导入 CLI/signer，
> 与密钥存储、重组、签名运行在**同一进程**（单进程架构）。
>
> **单进程架构下的安全边界**：
> - ✅ **已实现**：凭证隔离——口令/恢复码/私钥/助记词**明文永不经 LLM 上下文**
>   （`passphrase_token` / `recovery_file_path` / `recovery_codes_file` 三通道）
> - ✅ **已实现**：口令加密设备分片（scrypt + AES-GCM）、2-of-3 门限、私钥用完内存清零
> - ⚠️ **未实现（路线图）**：独立签名守护进程、本地 IPC、Keychain/Keystore、
>   OS 弹窗——**MCP 进程被攻破 = 攻击者拥有与 CLI/signer 相同的文件系统权限
>   和代码执行能力**，可读恢复码文件并重组钱包。在独立进程落地前，本项目的
>   安全承诺是「凭证不进 LLM」，而非「MCP 被攻破拿不到密钥」。

### 目标架构（路线图）

```
MCP server（无密钥）→ 本地 IPC → 签名守护进程（唯一持钥者）
```

- MCP 层被攻破：拿不到任何密钥（需独立进程落地）
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
| 用户设备被控 | 口令加密分片 + 2-of-3 门限 | 设备完全沦陷时明文恢复码文件可读（单进程架构下 MCP 同权限）；Keychain + OS 弹窗为路线图目标，未落地 |
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

> 全量 121/121 测试全绿（含：CRC 篡改、地址不匹配、无效令牌、口令强度、P0-2 事务落盘、P1-1 签名地址校验、P1-3 损坏 metadata、P1-5 畸形签名结构化错误）。

### 2026-08-10 深入审查修复（三视角并行：完整性 × 正确性 × 影响面）

| 级别 | 问题 | 修复 |
|------|------|------|
| 🔴 Critical | `wallet_restore` 绕过凭证隔离：恢复码×2 入参 + 明文出参全进 LLM | 输入改本地文件读取（`recovery_file_path`）；输出改 `recovery_codes_file`+`note`；min(12)；新增 expected_address/email 参数与 2 条功能测试 |
| 🟠 Warning | `signMessage`/`createUnlockToken` 异常路径私钥残留 | `vault.wipe()` 移入 finally；privateKey null 初始化 + finally 清零 |
| 🟠 Warning | init/restore 恢复码落盘不在原子/回滚范围 | 落盘前置（失败不再产生锁死态）；meta/device/recovery 三文件统一回滚 |
| 🟠 Warning | 地址交叉校验新设备场景失效 / 邮箱更新指引不可执行 | CLI/MCP 暴露 `expected_address`；`restoreWallet` 新增 email 参数自动发送新片③ |
| 🟡 Suggestion | CLI 恢复码回显 / user_id·action 无校验 / 裸 0x19 / schema 0x 漂移 | 掩码输入；action 白名单+user_id 校验；`\x19` 转义；schema 去 0x |
| 🔴 **口令令牌** | **`wallet_create`/`wallet_restore` 口令参数仍进 LLM（最后残余凭证）** | **`passphrase_token` 机制**：CLI `passphrase-token` 本地输入口令 → 生成口令会话令牌（`passphrase-*` 文件，5min/0600/单次）；MCP 工具只接收令牌，口令明文永不经 LLM——**口令+恢复码全部凭证闭环** |

> 全量 121/121 测试全绿。

### 2026-08-11 外部审查修复（Codex 辩证核查）

| 级别 | 问题 | 修复 |
|------|------|------|
| 🔴 P0 | CLI 测试 beforeEach 先删 `getHomeDir()` 后设 env——未预设 `SHARDNEST_HOME` 时删除真实 `~/.shardnest` | env 移至模块加载阶段 + 删除点路径守卫（含 `.test-shardnest-` 断言）；哨兵验证确认不再触碰真实目录 |
| 🔴 P0 | 覆盖旧钱包失败时「回滚」删除旧钱包全部文件 | 事务式落盘：staging（O_EXCL）→ fsync → 原子 rename；失败时正式路径零接触 |
| 🟠 P1 | `signMessage` 无地址交叉校验（错恢复码签出另一地址） | 与 `createUnlockToken` 对齐，派生后地址与 metadata 不一致即拒绝 |
| 🟠 P1 | 损坏 metadata 被 `readOldAddress` 吞掉 → 绕过 init 防覆盖 | 仅 ENOENT 视为不存在；JSON 损坏/缺字段/权限错误一律硬失败 |
| 🟠 P1 | 协议 Schema `platform_signature` pattern 128 与实现 130 hex 矛盾 | Schema 修正为 130 hex（65 字节 r‖s‖v） |
| 🟠 P1 | 验签对畸形输入抛库异常（非结构化错误） | `platform_signature` 严格 130 hex 预校验 + `recoverSigner` try/catch + expectedPlatformAddress 格式校验 |
| 🟡 中风险 | KDF 参数无上限（篡改 N/r/p 内存 DoS）| `kdfParamsOf` 参数上限（N≤2^20 且 2 的幂）|
| 🟡 中风险 | 口令/KEK 字节未清零、shamir shares 无 255 上限、0600 不收紧已有文件 | `deriveKEK` 口令清零、`encryptShare`/`decryptShare` KEK 清零、shares≤255 + index∈[1,255] 校验、rename 后 chmod + 目录 0700 |

### 2026-08-12 剩余问题修复（P0-3 / P1-2 / P1-6 / P1-7）

| 级别 | 问题 | 修复 |
|------|------|------|
| 🔴 P0-3 | 文档宣称进程隔离/IPC/Keychain 已实现（实际单进程）| 文档区分「已实现/路线图」；明确当前承诺是「凭证不进 LLM」而非「MCP 被攻破无密钥」 |
| 🟠 P1-2 | 恢复码无钱包/批次绑定——混用两套恢复码静默创建第三方钱包 | `sn2` 格式加随机 `share_set_id`，同批分片必须一致 |
| 🟠 P1-6 | 钱包签名仅 `action:intent_hash`，可脱离请求传播 | 签名内容绑定 `wallet_address` + `nonce`（域分离）|
| 🟠 P1-7 | 口令令牌不区分 create/restore 操作 | 令牌绑定操作类型（create/restore 前缀隔离）|

## 已知边界（诚实披露）

1. **物理抹除不保证**：APFS/SSD 等 copy-on-write 文件系统上，`secureDelete` 的 3 遍覆写**无法保证物理抹除**（覆写可能落到新块，旧块仍可被取证恢复）。本机制主要防**软件层**恢复（普通文件读取/回收站/简单恢复工具）。追求物理抹除需全盘加密 + 介质销毁。
2. **平台必须校验地址绑定**：`signed_request_sign` 的签名内容为 `action:intent_hash`（不含 `wallet_address`）。签名防重放/防冒用依赖平台侧用 `verify-sdk` 的 `recoverSigner(message, sig)` 还原地址并与绑定的 `wallet_address` 比对——**平台必须做该绑定校验**，仅验签名有效性不足以防跨地址重放。
3. **scrypt 参数**：N=2^17（约 128MB/次，OWASP 2023 下限）——本地单用户可接受；参数随密文持久化（O1），未来可平滑调高。

## 依赖审计要求

- 密码学依赖：noble-curves / noble-hashes（审计级、纯 TS、零依赖）
- SSS：自研 GF(256) 实现 + 向量测试（tests/）
- 任何新增密码学依赖必须附审计/来源说明
