# shardnest 钱包服务 · 安全 / 架构 / 加密 综合审查报告

**审查日期**：2026-08-12
**审查视角**：架构师 · 安全专家 · 加密专家
**审查范围**：`packages/{core,signer,cli,verify-sdk,protocol,mcp-server}` 源码、`docs/SECURITY.md`、`docs/DES-016-*.md`、协议 schema、145 个测试用例
**结论摘要**：项目经历过多次专家审查，整体质量高，**未发现致命密码学缺陷**。声明的 7 条密码学不变式（生成元=3、EIP-191 三处一致、恢复码 CRC 覆盖 index:hex、私钥范围校验、内存清零、地址交叉校验、原子性）均正确落地。主要风险集中在**架构层面（单进程）**与**少量中危交互/协议细节**，无阻断上线的致命问题，但上线真实资金前须修复 P0 两项。

---

## 一、总览评分

| 维度 | 评级 | 说明 |
|------|------|------|
| 密码学正确性 | **A** | GF(256)/SSS/ECDSA/AES-GCM/scrypt 实现正确，不变式全部成立 |
| 密钥隔离 | **A-** | 凭证不进 LLM、0600/0700、令牌单次+5min TTL、内存清零到位 |
| 安全边界 | **B+** | 双闸门+默认拒绝成立；但 MCP 错误响应漏 `isError`、display 未签名 |
| 架构韧性 | **B** | 分层清晰无环；**单进程架构**为最大结构性风险（路线图 P0-3 未落地） |
| 测试覆盖 | **A-** | 145 用例，负向路径（CRC 篡改/地址不匹配/坏令牌/弱口令/原子回滚）齐全 |

---

## 二、加密专家视角

### ✅ 已正确实现（无需改动）
1. **GF(2⁸) 生成元=3（不变式 1）**：`shamir.ts` 以 `x*=3` 建 EXP/LOG 表，3 为阶 255 的本原元，表完整无缺漏；注释对"元素 2 阶仅 51"的说明准确。
2. **EIP-191 哈希三处字节级一致（不变式 2）**：`vault.ts` / `protocol/signed-request.ts` / `verify-sdk/index.ts` 的 `personalMessageHash` 实现逐字节相同，且 `personalMessageHash(canonicalBytes(base))` 与 `recoverSigner` 内部包装一致——签发/验签闭环自洽。
3. **SSS 正确性**：逐字节独立多项式、阈值 `t` 强制 `2≤t≤n`、`index∈[1,255]`、`shares≤255`、重复 index 拒绝；`reshare` 后旧分片数学上仍有效（已文档化须物理清理旧载体）。
4. **AES-GCM 防重放**：`encryptShare` 每次生成新 12 字节随机 nonce；GCM 认证失败被捕获并转为"口令错误"友好提示（I10）。
5. **恢复码 CRC 覆盖 `index:hex`（不变式 3）**：`sn2` 额外绑定 8 字节 `setId`，跨钱包混用被 `assertSameShareSet` 拒绝；`sn1` 兼容旧 crc8 并新增 crc32。
6. **私钥范围校验（不变式 4）**：`WalletVault.assertValidPrivateKey` 校验 `0<priv<n`，防组合出坏私钥静默签名。
7. **内存清零（不变式 5）**：`deriveKEK`/`encryptShare`/`decryptShare` 的 KEK、`combineShares` 后的 entropy、各 `finally` 中的私钥/分片均 `fill(0)`；`passphrase` 字符串不可变已注明仅置空引用。

### ⚠️ 中/低危（建议优化）
- **[中] `combineShares` 对分片无来源认证**：传入超过阈值的分片时全部参与插值，混入错误分片会静默产出垃圾熵。当前仅依赖"设备分片 GCM 认证 + 恢复码 CRC + 地址交叉校验"三重兜底——在 `want`（本地 metadata 或 expected_address）存在时有效；legacy `sn1` 且无 `want` 时 `restoreWallet` 已主动拒绝。**建议**：对分片增加密码学绑定（如每个 share 附带 `HMAC(KEK, share)` 或承诺），或严格限定只接受恰好 `threshold` 个分片。
- **[低] `lagrangeInterpolate` 暴力求逆**：每个分母 256 次循环。仅性能问题（阈值大时 `32·t·256` 次运算），可预建逆元表，不影响安全。
- **[低] 解锁令牌文件名泄露前缀**：`createUnlockSession` 用 `token.slice(0,16)`（256 位令牌的前 64 位）作文件名。注释称"防本地枚举"实为误导——它反而**暴露**了前缀；剩余 192 位仍不可爆破，影响可忽略。建议修正注释或改用 `sha256(token)` 作为文件名（不泄露任何令牌位）。
- **[低] `generatePrivateKey` 成功路径未清零局部 `bytes`**：返回的字节数组即私钥，清理责任在调用方；`generateKeyPair`→`vault` 链路最终由 `wipe` 清零，可接受。

---

## 三、安全专家视角

### 🔴 P0 — 必须修复（上线真实资金前）
**1. MCP 工具错误响应缺失 `isError: true`（安全闸门完整性受损）**
所有显式错误返回（如 `USER_REJECTED`、`WALLET_ADDRESS_MISMATCH`、`UNLOCK_INVALID`、`NO_WALLET`、`RESTORE_FAILED`、`PLATFORM_ADDRESS_NOT_CONFIGURED` 等）均为：
```ts
return { content: [{ type: 'text', text: JSON.stringify({ error: '...' }) }] }
// 缺少 isError: true
```
按 MCP 规范，不置 `isError` 时客户端/LLM 视其为**成功结果**。后果：双闸门中任一被拒（用户拒绝、地址不符、令牌失效）时，LLM 可能误判"签名成功"并继续后续动作（如向用户报告已签名）。`isError` 仅在 handler **抛异常**时由 SDK 自动设置（测试 `mcp.test.ts:272` 验证的是此路径）。
**修复**：在每个错误返回对象加 `isError: true`（可抽一个 `errResult(code, msg)` 辅助函数统一处理）。这是本次审查发现的**最高危交互缺陷**。

### 🟠 P1 — 强烈建议
**2. `display` 未纳入钱包签名（所见即所签缺口）**
用户批准依据的是平台下发的 `display` 文案，但 `walletSignMessage` 只签名 `intent_hash`（不含 `display`）。`display` 虽被平台背书签名覆盖（`canonicalBytes` 含 display），但钱包侧签名与用户看到的文案**无密码学绑定**：若平台被攻破，可在 `display` 显示"A"、却以 `intent_hash` 承诺"B"，用户按其看到的"A"批准，钱包签出的却是"B"的承诺。
**修复**：将 `display`（或其哈希）以 length-prefixed 形式并入 `walletSignMessage`（需平台验签端同步升级，建议 v3 字段），使签名内容 = 用户所见。

**3. 重放防护完全委托平台**
`verifySignedRequest` 仅校验 `nonce` 格式（≥16 位）与时效，**不跟踪 nonce 是否已用**。钱包无状态，若平台因 bug/被攻破在有效期内复用 nonce，`sign_message` 会被再次签名出相同结果。
**修复**：钱包侧维护短时（≤expires_at 窗口）已用 nonce 缓存；或在文档显著位置强调"nonce 一次性消费是平台唯一责任，钱包不兜底"。

**4. 口令强度仅校验长度 ≥12**
`validatePassphrase` 仅查长度，无熵/复杂度评估。`device-share.json` 落盘后，离线攻击者可用 scrypt N=2¹⁷（≈128MB）暴力破解；12 位低熵口令可被攻破。2-of-3 的安全性在此场景下**等价于口令强度**。
**修复**：引入 `zxcvbn` 类强度评估并设阈值；评估将 scrypt 提升至 N=2¹⁸–2¹⁹ 或迁移 Argon2id；文档明确"口令即单点"。

**5. 口令令牌 purpose 校验可被调用方绕过**
`consumeUnlockSession` 仅在 `if (purpose && ...)` 时校验操作绑定。当前所有调用方都传 `purpose`（`create`/`restore`），故当下安全；但未来若某调用方遗漏 `purpose`，create/restore 绑定即被静默绕过。
**修复**：口令会话消费时 `purpose` 设为必填，缺省直接抛错。

### 🟡 P2 — 低危/加固
- **[低] `wallet_address` 暴露钱包存在性**：返回明文地址或 `'NO_WALLET'`，泄露本机是否持有钱包。本地场景可接受，远程/多租户场景需收敛。
- **[低] 邮件 TLS/STARTTLS 配置歧义**：`mailer.ts` 用 `secure: config.tls`（默认 true），对 465 隐式 TLS 正确，但对 587/25（STARTTLS）应设 `requireTLS` 且 `secure:false`。误配可能降级或失败。
- **[低] SMTP 口令存于环境变量明文**：属服务端密钥，可接受，但建议经密钥管理/文件注入而非进程环境。

### ✅ 安全亮点（保持）
- 凭证三通道隔离（`passphrase_token` / `recovery_file_path` / `recovery_codes_file`）彻底闭环，明文凭证零进 LLM。
- `defaultApproval` 仅放行 `sign_message`：开箱即用的 MCP **无法** wipe / 导出助记词 / 签交易——高危操作默认全拒，须宿主注入 approval handler。
- 事务式原子提交 + 备份回滚（P0-2），`secureDelete` 3 遍覆写 + 符号链接/硬链接/TOCTOU(inode) 防护，`WIPE_CONFIRM_PHRASE` 二次确认。
- `verifySignedRequest` 结构化校验（格式/时效/130-hex 签名/平台地址），畸形输入不抛库异常。
- 解锁会话：rename 原子消费保证单次语义、5min TTL、0600 落盘、启动清理过期文件减少侧信道。

---

## 四、架构师视角

### 🔴 P0 — 结构性风险
**6. 单进程架构（路线图 P0-3 未落地）**
`SECURITY.md` 已诚实声明：当前 MCP server 直接 `import` CLI/signer，**与密钥存储、重组、签名同进程**。"MCP 被攻破 = 攻击者拥有与 CLI/signer 相同的文件系统权限与代码执行能力，可读恢复码文件并重组钱包。"
目标架构（独立签名守护进程 + 本地 IPC + Keychain/TEE + OS 原生弹窗）尚未实现。这是**最大的结构性风险**，也是审查记录中反复列为 P0-3 的待办。
**建议**：优先落地——signer 作为独立、沙箱化、仅持钥进程；MCP 经 IPC 通信；批准走 OS 原生提示；密钥优先存 OS Keychain/安全 enclave。

### 🟠 P1
**7. 安全默认值导致功能不完整**
`defaultApproval` 仅放行 `sign_message`，意味着交易签名/绑定/提现/导出助记词/wipe 在宿主未注入 approval handler 前**全部不可用**。安全姿态正确，但"平台集成"故事在宿主实现确认 UI 前不成立。建议在文档/SDK 中明确宿主必须实现的 approval 契约与示例。

### 🟡 P2
- **[低] `@ts-expect-error TS2589`** 在 `mcp-server` 压制 SDK 泛型深度报错（运行时无影响），但掩盖类型漂移，建议封装 typed wrapper 或升级 SDK。
- **[低] `signed_request` 入参 `z.unknown()`**：字段校验在 `verifySignedRequest` 内手写（正确），但工具 schema 不约束形状，畸形输入直达 handler（已优雅处理）。建议用 zod schema 镜像 JSON schema，提前拒绝并改善 LLM 入参体验。
- **[低] 依赖卫生**：lockfile 存在（好）；crypto 库用 `^1.4.0` 范围。建议 CI 中加入 `osv-scanner`/`npm audit`，并对 noble/scure 等关键库考虑锁定精确版本。当前 noble v1.4、scure、zod 3.23、MCP 1.30 均为较新版本。

### ✅ 架构亮点（保持）
- 包分层严格单向：`core ← signer ← {cli, verify-sdk, protocol} ← mcp-server`，无循环依赖。
- 纯密码学 `core` 零 IO；`verify-sdk` verify-only 零密钥；协议层确定性 length-prefixed 二进制消除跨语言歧义。
- 测试充分（145 例），负向路径覆盖完整，含跨包闭环（签发→验签→还原）。

---

## 五、优先级与行动清单

| 级别 | 编号 | 问题 | 建议动作 |
|------|------|------|----------|
| **P0** | 1 | MCP 错误响应漏 `isError` | 所有错误返回补 `isError: true`（统一辅助函数） |
| **P0** | 6 | 单进程架构 | 落地独立签名守护进程 + IPC + Keychain/OS 弹窗 |
| **P1** | 2 | display 未签名 | 将 display 并入 `walletSignMessage`（v3 协调升级） |
| **P1** | 3 | 重放全委托平台 | 钱包侧加短时 nonce 去重缓存 / 强化文档责任边界 |
| **P1** | 4 | 口令仅长度校验 | 加强度评估 + 提升 scrypt/迁移 Argon2id |
| **P1** | 5 | purpose 可绕过 | 口令会话 purpose 必填 |
| **P2** | — | 邮件 TLS 配置、令牌文件名前缀、lagrange 性能、依赖锁定、`@ts-expect-error` | 逐项加固 |

---

## 六、补充测试建议
1. 新增**三方可复现一致性**测试：vault 签名 → `verify-sdk.recoverSigner` 用**同一** `walletSignMessage` 字节验签通过。
2. 新增**分片替换负向测试**：构造 1 真 + 1 假恢复码，`combineShares` 后地址交叉校验必须拒绝。
3. 新增测试断言 MCP 错误返回携带 `isError: true`。
4. 对 `canonicalBytes` / `walletSignMessage` 的 length-prefix 解析加模糊测试（超长/零长/恶意长度）。

---
*审查基于静态代码阅读与跨包一致性核对，未做动态渗透/依赖 CVE 扫描。如需，我可补充：依赖漏洞扫描（osv-scanner）、针对 #1/#5 的最小修复补丁、或 P0-3 独立签名进程的详细设计。*

---

## 七、加固进展（2026-08-12 续 · 安全工程师落地）

审查报告中承诺的"未完成任务"已推进如下：

### 7.1 依赖漏洞扫描（OSV）✅ 完成
- 解析 `bun.lock` 全部 **109 个解析版本**，经 OSV API 批量查询。
- **结果：0 个已知 CVE / 漏洞**。关键密码学库均处安全版本：
  `@noble/ciphers@1.3.0`、`@noble/curves@1.9.7`、`@noble/hashes@1.8.0`、`@scure/bip32@2.3.0`、`@scure/bip39@1.6.0`、`nodemailer@9.0.5`、`@modelcontextprotocol/sdk@1.30.0`、`zod@3.25.76`（及 mcp 内嵌 `zod@4.4.3`）、`typescript@5.9.3`。
- 结论：依赖卫生维度无新增风险，与 P2 建议"CI 加 osv-scanner"一致——建议将本扫描固化进 CI。

### 7.2 P0-1（MCP 错误响应 isError）✅ 已修复并通过测试
- 代码已落地统一 `errResp()` 辅助函数，**全部 23 处显式错误返回均带 `isError: true`**（覆盖 `USER_REJECTED` / `WALLET_ADDRESS_MISMATCH` / `UNLOCK_INVALID` / `NO_WALLET` / `RESTORE_FAILED` / `PLATFORM_ADDRESS_NOT_CONFIGURED` / `ADDRESS_MISMATCH` / `WIPE_FAILED` / `EXPORT_FAILED` / `NEED_SECOND_RECOVERY_CODE` 等）。
- 回归测试：`mcp.test.ts` 现有 **11 处 `expect(res.isError).toBe(true)` 断言**全部通过，双闸门拒绝不会再被 LLM 误判为成功。

### 7.3 P1-7（passphrase purpose 绑定）✅ 加固并补回归测试
- 原校验 `if (data.purpose && purpose !== data.purpose)` 对"误建的 null-purpose 口令会话"存在理论绕过窗口。
- 加固为：对 `type === 'passphrase'` 会话直接比较 `purpose !== data.purpose`（含 null 必须相等），**同时封死两个窗口**：
  1. 调用方漏传 purpose → 拒绝；
  2. 经底层 `createUnlockSession(bytes,'passphrase')` 误建的 null-purpose 会话 → 拒绝（无 purpose 绑定 = 无约束，等同绕过）。
- 仅作用于 passphrase 类型，`unlock`（私钥解锁）会话无操作语义、不受影响。
- 新增回归测试（`unlock-session.test.ts`）：误建 null-purpose 会话 + 漏传 purpose 两条均断言拒绝。

### 7.4 P0-3（独立签名守护进程）✅ 设计完成
- 新增详细设计文档 `docs/DES-017-isolated-signing-daemon.md`：三进程信任边界、最小攻击面职责、本地认证 IPC 协议（HMAC + 防重放 + length-prefixed 二进制）、OS 原生批准弹窗（呼应 P1-2 所见即所签）、Keychain/secure enclave 密钥存储、seccomp/App Sandbox 沙箱、4 阶段向后兼容迁移路线、验收标准。

### 7.5 验证结果
- 全量测试：**147 pass / 0 fail**（core 30 · signer 12 · cli 57 · verify-sdk 5 · protocol 22 · mcp-server 21）。
- 类型检查：`bunx tsc --noEmit` 通过，无错误。

### 7.6 剩余待办（建议下一轮）
- 审查报告中标为"未签名/仅长度校验"的 **P1-#2（display）** 与 **P1-#4 基础校验** 经代码核实**已落地**（walletSignMessage 为 v3 含 display 域分离签名；validatePassphrase 已实现字符类/重复/序列校验）。故真正剩余的 P1 项为 #3（重放）与 #4 的熵下限——均已在第二轮加固中处理（见 7.7 / 7.8）。
- **[P2]** 邮件 TLS/STARTTLS 配置、令牌文件名前缀、lagrange 性能、依赖锁定固化进 CI、`@ts-expect-error` 封装。
- 建议将 OSV 扫描 + `bun test` 固化进 CI，防止依赖与回归回归。

### 7.7 第二轮加固（2026-08-12 续 · P1-#3 / P1-#4）

- **P1-#3（重放全委托平台）→ 已加固**：新增 `packages/mcp-server/src/replay-guard.ts`（`ReplayGuard` 类），在 `signed_request_sign` 验签通过后、**消费解锁令牌前**拦截已用 nonce（key = `platformAddress:nonce`，惰性清理过期条目）。即使平台因 bug/被攻破在有效期内复用 nonce，钱包侧也能拒绝重放。新增回归测试：`mcp.test.ts`「P1-3：同 nonce 重放 → NONCE_REUSED」。
- **P1-#4（口令仅长度校验）→ 已加固（两层）**：
  1. `validatePassphrase` 新增**香农熵下限（≥30 bits）**，捕获"表面多类、实质弱"的口令（如 `Aaaaaaaaaaaa1` 约 10 bits 被拒）；辅助函数 `estimatePassphraseEntropy` 基于字符经验频率分布。新增回归测试：`commands.test.ts`「P1-4：低熵口令 → 拒绝」。
  2. scrypt KEK 成本 `SCRYPT_OPTS.N: 2^17 → 2^18`（128MB→256MB，仍在上限 2^20 内；旧钱包 KDF 参数随密文持久化，向后兼容）。直接提高弱口令离线暴力破解成本。测试断言 `device-share.json` 持久化 N 同步更新为 `2^18`。

### 7.8 验证结果（第二轮）
- 全量测试：**149 pass / 0 fail**（core 30 · signer 12 · cli 58 · verify-sdk 5 · protocol 22 · mcp-server 22）。
- 类型检查：`bunx tsc --noEmit` 通过。
- 关键文件：`packages/mcp-server/src/replay-guard.ts`（新增）、`packages/mcp-server/src/index.ts`（接入重放防护）、`packages/cli/src/commands.ts`（熵下限）、`packages/core/src/keys.ts`（scrypt 成本）。

### 7.9 剩余待办（建议后续轮次）
- **[P2]** 邮件 TLS/STARTTLS 配置歧义、令牌文件名前缀泄露（建议改用 `sha256(token)`）、lagrange 逆元表性能、`@ts-expect-error` 封装、依赖锁定固化进 CI（osv-scanner）。
- **[架构]** P0-3 独立签名守护进程：设计已完成（`docs/DES-017-isolated-signing-daemon.md`），待按 4 阶段路线落地（Phase 1 抽离 + IPC 即可最快消除单进程主风险）。
