---
title: shardnest 第三方接入指南
date: 2026-08-09
status: active
last_reviewed: 2026-08-09
tags: ['integration', 'third-party', 'signed-request', 'verify-sdk']
---

# 第三方接入指南（INTEGRATION）

> 面向**业务平台**（任何需要用户钱包签名确认的平台）的完整接入说明。
> 核心原则：平台**零密钥材料**——用户钱包完全自持，平台仅验签。

---

## 架构总览

```
用户 Agent 环境：
├── MCP server ① 业务平台     （业务 + 地址绑定 + signed_request 签发）
├── MCP server ② shardnest    （独立开源；签名/分片/恢复）
└── 交互：平台签发 → Agent 转发给钱包服务 → 签名返回平台
```

- 平台持有：平台背书私钥（签发用）、用户 `wallet_address`（公开信息）
- 平台不持有：用户口令、恢复码、私钥、助记词——**任何密钥材料**
- 钱包地址绑定 = 验签证明所有权；提现 = 签名确认

---

## 第一步：安装依赖

```bash
# 平台侧需要：protocol（签发）+ verify-sdk（验签）
bun add @wallet-service/protocol @wallet-service/verify-sdk
# 或从源码 workspace 引用
```

**平台必须配置**：`SHARDNEST_PLATFORM_ADDRESS`（钱包服务的启动环境变量）= 平台背书地址。

## 第二步：签发 signed_request（平台侧）

```ts
import { issueSignedRequest } from '@wallet-service/protocol'

// 平台自持私钥（仅用于签发背书；用完即弃）
const request = issueSignedRequest({
  action: 'withdraw_confirm',          // 业务动作（sign_message/sign_tx/bind_wallet/withdraw_confirm）
  intentHash: '0x' + 'ab'.repeat(32),  // 业务意图哈希（如提现单哈希）
  display: '确认提现 0.5 ETH 到 0x...',  // 用户可见描述
  userId: 'user-42',
  walletAddress: '0x7E5F...',          // 目标钱包地址（绑定过的）
  nonce: crypto.randomUUID(),          // 一次性，防重放（平台侧原子消费）
  expiresAt: Math.floor(Date.now()/1000) + 300,  // 5 分钟有效
}, platformPrivateKey)
```

**序列化规范**（canonicalBytes，跨语言必须一致）：
`v(1B) | action(len4+utf8) | intent_hash(len4+32B) | display(len4+utf8) | user_id(len4+utf8) | wallet_address(len4+20B) | nonce(len4+utf8) | expires_at(8B BE)`
——UTF-8 字节 + 4 字节大端长度前缀；**勿用 JSON 字符串**（Unicode/整数歧义会导致验签失败）。

## 第三步：Agent 侧签名（钱包服务）

用户 Agent 调用 MCP `signed_request_sign`（参数 `signed_request` + `unlock_token`）：

1. 闸门 1：钱包服务验签背书（`verifySignedRequest`）——非平台签发即拒绝
2. 闸门 2：宿主 approval（默认仅放行 `sign_message`；其他动作需宿主配置）
3. `wallet_address` 与本地钱包一致校验
4. 消费解锁令牌（单次）→ 本地签名 `action:intent_hash` → 返回 `{ address, signature }`

## 第四步：平台验签（verify-sdk）

```ts
import { recoverSigner } from '@wallet-service/verify-sdk'

const { message, signature } = signedResponse   // signature: 65 字节 r||s||v（hex）
const recovered = recoverSigner(message, hexToBytes(signature))
if (recovered.toLowerCase() !== boundWalletAddress.toLowerCase()) {
  throw new Error('签名地址与绑定地址不一致——拒绝')
}
```

**平台必须做地址绑定校验**（仅验签名有效性不足以防跨地址重放）。

## 地址绑定流程

1. 用户创建钱包（CLI `init` 或 MCP `wallet_create`）→ 得到 `wallet_address`
2. 平台发起绑定：签发 `action: 'bind_wallet'` 的 signed_request
3. 用户签名（`signed_request_sign`）→ 平台验签还原地址 → 与用户声明的地址一致 → 绑定成功
4. 绑定后 `agents` 表存 `wallet_address`（公开信息，非密钥）

**换绑**：先提现余额 → 解绑 → 用新钱包重新绑定。

## 提现流程（签名确认）

```
用户发起提现 → 平台生成提现单 → 签发 withdraw_confirm signed_request
→ Agent 调用 signed_request_sign → 平台验签 + 地址绑定校验 → 通过后执行转账
```

## 错误码（MCP 工具返回）

| error | 含义 | 处理 |
|-------|------|------|
| `BAD_SIGNATURE` | 平台背书验签失败 | 检查平台地址/签发实现（canonicalBytes 一致性） |
| `EXPIRED` / `INVALID_FORMAT` | 请求过期/格式错误 | 重新签发 |
| `ACTION_NOT_ALLOWED` | action 不在白名单 | 检查 action 枚举 |
| `WALLET_ADDRESS_MISMATCH` | 目标地址与本地钱包不一致 | 检查 wallet_address 参数 |
| `USER_REJECTED` | 用户/宿主拒绝 approval | 提示用户确认 |
| `NO_WALLET` | 本地无钱包 | 先 wallet_create/CLI init |
| `WALLET_EXISTS` | 钱包已存在（create 被拒） | 需 wipe（宿主 approval）或 CLI 确认 |
| `TOKEN_EXPIRED` / `TOKEN_CONSUMED` | 令牌过期/已用 | 重新生成令牌 |
| `NEED_SECOND_RECOVERY_CODE` | 恢复需 2 个恢复码 | 补充输入 |

## 安全要求（平台侧必读）

1. **平台零密钥材料**——不收集/存储用户口令、恢复码、私钥、助记词
2. **nonce 原子消费**——防重放
3. **地址绑定校验**——提现/敏感操作前必须验签还原地址并与绑定地址比对
4. **背书私钥安全**——平台私钥用安全存储（KMS/HSM），仅签名不导出
5. **提示用户**——display 文案清晰描述用户将要确认的内容

## 参考

- 协议细节：[protocol/README.md](../protocol/README.md) + [signed-request-v1.schema.json](../protocol/signed-request-v1.schema.json)
- 验签 SDK 用法：[packages/verify-sdk/src/index.ts](../packages/verify-sdk/src/index.ts)
- 端到端演练：[TUTORIAL.md](TUTORIAL.md)
