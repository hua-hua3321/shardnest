# DES-017 · 隔离签名守护进程（P0-3 落地设计）

**关联**：`DES-016-self-custodial-wallet-service.md`、`SECURITY.md`、审计报告 `SECURITY-REVIEW-2026-08-12.md`
**状态**：设计草案（待评审）
**目标**：消除"单进程架构"这一最大结构性风险——MCP server 与密钥存储/重组/签名**同进程**，导致"MCP 被攻破 = 攻击者拥有与 CLI/signer 同等的文件系统权限与代码执行能力，可读恢复码文件并重组钱包"。

---

## 1. 威胁模型与目标

### 1.1 当前（P0-3 未落地）信任边界
```
┌─────────────────────────────────────────────┐
│  单进程（MCP server 直接 import cli/signer）    │
│  · 平台背书验签（verifySignedRequest）          │
│  · 用户确认闸门（approval handler）             │
│  · 读取 recovery-codes.txt / device-share.json │  ← 密钥材料与 MCP 同地址空间
│  · combineShares → 私钥重组                     │
│  · WalletVault 签名                            │
│  · 内存私钥清零（finally）                      │
└─────────────────────────────────────────────┘
   ↑ LLM/客户端 通过 stdio 与该进程对话
```
**问题**：MCP 层（含第三方 SDK、zod 解析、InMemoryTransport、任何未来新增的传输/集成）一旦被攻破或被供给恶意工具描述，即可直接触达本机 wallet 目录、恢复码明文、以及已解锁的私钥。现有"凭证三通道 + 内存清零"的防护在**同进程**下只能降低泄露概率，无法提供进程级隔离。

### 1.2 目标信任边界
```
┌──────────────┐  本地 IPC(认证)   ┌──────────────────────────┐   OS Keychain/TEE
│ Host / MCP    │ ───────────────▶ │ Signing Daemon(仅持钥)     │ ───────────────▶
│ · 验平台背书   │   最小攻击面请求   │ · unlock/recombine         │   密钥加密存储/
│ · 用户确认转发  │ ◀─────────────── │ · sign（私钥不出 daemon）   │   安全 enclave
│ · 无密钥材料   │   签名结果         │ · wipe                     │
└──────────────┘                   └──────────────────────────┘
   ↑ LLM/客户端                         ↑ OS 原生批准弹窗（Touch ID / 密码）
```
**安全增益**：
1. MCP 进程被攻破时，**拿不到任何持久化密钥材料**——密钥仅在 daemon 内重组、签名后立即清零；恢复码/device-share 由 daemon 独占读取。
2. 签名动作需经 **OS 原生批准**（daemon 触发，不依赖 LLM 上下文），实现"所见即所签 + 本地强确认"。
3. 密钥优先驻留 **OS Keychain / secure enclave / TPM**，私钥字节尽量不进入 daemon 普通堆内存。

---

## 2. 守护进程职责（最小攻击面）

守护进程**只**暴露以下能力，且每个能力受批准闸门约束：

| 能力 | 输入 | 输出 | 批准要求 |
|------|------|------|----------|
| `Ping` | 心跳 | `ok` | 无 |
| `GetAddress` | 无 | 钱包地址（明文，非秘密） | 无 |
| `Unlock` | `device_share` 解密凭据（口令 token / 恢复码文件路径） | 一次性 unlock 句柄（本地） | OS 原生确认 |
| `Sign` | 已签名的 `walletSignMessage` 字节 + unlock 句柄 | 签名（hex） | OS 原生确认（含 display 校验） |
| `Wipe` | 确认短语 | 删除清单 | OS 原生强确认（二次） |

守护进程**不持有**：平台地址配置、SMTP 配置、网络出站（除非显式启用备份邮件投递，且应隔离为独立最小权限子进程）、LLM 上下文、MCP 传输。

---

## 3. IPC 协议（本地、认证、防重放）

### 3.1 传输
- **macOS / Linux**：Unix domain socket `@shardnest-daemon` 或 `~/Library/Caches/shardnest/daemon.sock`（0700，绑定前 `unlink` 防残留）。
- **Windows**：命名管道 `\\.\pipe\shardnest-daemon`（ACL 限定当前用户）。
- 仅接受**本机、当前用户**连接；绑定地址不可被非特权用户预测/劫持。

### 3.2 认证
- daemon 启动时生成 **256-bit 共享 secret**（`randomBytes(32)`），通过**机密通道**传给 host：
  - 方式 A：daemon 将 secret 写入 `0600` 临时文件，host 读取后 daemon 立即删除（同机、同用户）。
  - 方式 B：daemon 监听前先由 host 通过本地 stdio 注入 secret（daemon 作为 host 子进程启动）。
- 每条 IPC 请求携带 `HMAC(secret, nonce ‖ request_body)`；daemon 校验 HMAC 防伪造/篡改。

### 3.3 防重放
- 每条请求带单调递增 `seq` + 随机 `nonce`；daemon 维护短时窗口（≤ 5min）已见 `(seq,nonce)` 集合，重复即拒。
- 请求体使用与 `signed_request` 一致的 **length-prefixed 二进制** 编码（复用 `core`/`protocol` 的 `canonicalBytes`），消除跨语言歧义。

### 3.4 请求/响应 schema（示例）
```
SignRequest  = version:u8 | seq:u64 | nonce:32B | hmac:32B | action:u8 | payload_len:u32 | payload
SignResponse = status:u8 | payload_len:u32 | payload   // payload = signature hex 或 错误码
```
错误码沿用现有 MCP 错误语义（`USER_REJECTED` / `UNLOCK_INVALID` / `WALLET_ADDRESS_MISMATCH` / …），**且必须带 `isError` 等价字段**（呼应 P0-1：拒绝≠成功）。

---

## 4. 批准闸门（OS 原生弹窗 · 所见即所签）

### 4.1 触发
daemon 在执行 `Unlock` / `Sign` / `Wipe` 前，**自己**弹出 OS 原生确认，不依赖 host 传入的 approval 结果（host 的 approval handler 仅作为额外的应用层策略，不替代 OS 确认）。

### 4.2 所见即所签（呼应 P1-2）
- `Sign` 弹窗展示的文案 = `display` 字段（来自平台背书，已被平台私钥签名覆盖）。
- daemon 在弹窗确认后，将 `display`（或其 `keccak` 哈希）以 length-prefixed 形式并入 `walletSignMessage`（即 P1-2 的 v3 字段），**使签名内容 = 用户所见**，彻底堵死"平台显示 A、承诺 B"的攻击。
- 用户看到的 `display` 与钱包签出的承诺密码学绑定，平台无法在用户按其所见批准时偷偷签出不同意图。

### 4.3 实现
- **macOS**：`Security` 框架 + Touch ID / 锁屏密码；或 `osascript` 弹 `display dialog`。
- **Linux**：`zenity` / `polkit` 前端。
- **Windows**：`Credential UI` / `TaskDialog`。
- 无图形环境时降级为 TTY 二次口令确认（并明确提示风险）。

---

## 5. 密钥存储（OS Keychain / secure enclave / TPM）

| 存储 | 私钥驻留 | 说明 |
|------|----------|------|
| 当前（`device-share.json` + 口令 KEK） | 文件（AES-GCM） | 保留为**兼容/降级**路径 |
| Keychain（macOS） | Keychain 项 | 口令 KEK 或私钥加密 blob 存入 Keychain；daemon 经 Keychain API 取用 |
| secure enclave / TPM | 永不出 enclave | 若平台支持，签名在 enclave 内完成，daemon 堆内存不出现明文私钥 |

**迁移原则**：新存储与现有 `~/shardnest/` 文件布局**并存**；优先 Keychain，缺失时降级文件；`reshare`/恢复后仍须提示物理清理旧载体（呼应不变式 7）。

---

## 6. 沙箱与加固

1. **进程沙箱**：
   - macOS：`App Sandbox`（仅 `~/shardnest` 与 Keychain  entitlement）或 `sandbox-exec` 最小 profile。
   - Linux：`seccomp-bpf` + `capabilities` 收紧（drop `CAP_NET_*` 除非需邮件子进程）+ `namespaces` 隔离。
   - 仅授权 daemon 读取 `~/shardnest/unlock`、`device-share.json`、`recovery-codes.txt`。
2. **文件权限**：会话目录 `0700`、文件 `0600`（现有不变式保持）。
3. **令牌会话**：沿用现有 `unlock` 单次 + 5min TTL + rename 原子消费（不变式 5/6 继续生效，只是文件改由 daemon 独占）。
4. **内存清零**：daemon 内所有组合出的熵/私钥/KEK 用后 `fill(0)`（现有 `finally` 模式保留并强化）。

---

## 7. 迁移路线（向后兼容）

| 阶段 | 内容 | 验收 |
|------|------|------|
| **Phase 1 · 抽离** | 将 `signer` 的 unlock/recombine/sign/wipe 抽为独立 daemon；MCP server 改为 IPC 客户端；文件存储布局不变 | MCP 进程内 `grep -r "WalletVault\|combineShares\|recovery-codes"` 为零；全量测试通过 |
| **Phase 2 · OS 批准** | daemon 触发 OS 原生弹窗；`display` 并入 `walletSignMessage`（P1-2 v3） | 无 OS 确认时签名被拒；篡改 display 验签失败 |
| **Phase 3 · Keychain** | 密钥优先存 OS Keychain/enclave；文件降级 | Keychain 不可用时自动降级并告警 |
| **Phase 4 · 沙箱** | daemon seccomp/App Sandbox 收紧 | 沙箱内越权文件访问被拒 |

**向后兼容**：Phase 1 即可消除"同进程持钥"主风险，且不改变用户/平台交互协议（`signed_request v1` 不变）。

---

## 8. 残余风险与验证

- **host → daemon 通道**：若 host 进程被完全控制，攻击者可向 daemon 发 IPC 请求；但每条请求仍需 **OS 原生批准**（用户必须亲自确认），且 daemon 仅持密钥、不持平台背书逻辑——无法伪造平台请求。
- **批准疲劳**：需限制单位时间内批准次数、对 `wipe` 强制二次确认（现有 `WIPE_CONFIRM_PHRASE` 保留）。
- **验证**：新增 daemon 集成测试——模拟 host IPC 调用，断言"未触发 OS 批准则签名失败"；断言 `isError` 语义在 IPC 层一致；断言 `display` 篡改阻断签名。

---

## 9. 验收标准（Definition of Done）

1. MCP server 源码中**不再 import** `WalletVault` / `combineShares` / 直接读 `recovery-codes.txt`。
2. 密钥重组与签名**仅**发生在 daemon 进程内；MCP 进程堆内存扫描无明文私钥。
3. 每次 `Sign`/`Wipe` **必须**经过 OS 原生批准，且 `display` 被密码学绑定进签名（P1-2 闭环）。
4. `signed_request v1` 协议与现有 145+ 测试**零改动**通过；新增 daemon IPC + OS 批准测试。
5. 单进程架构风险项从 P0 降为已缓解（N/A 或文档化残余风险）。

---

*本设计为 P0-3 的落地蓝图。具体实现前应结合目标平台（macOS/Linux/Windows）的 Keychain/沙箱 API 做 PoC 验证，建议从 Phase 1（抽离 + IPC）起步以最快消除主风险。*
