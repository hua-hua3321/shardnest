# 协议规范

## signed_request v1

钱包服务与业务平台之间的**唯一耦合点**。任何平台只要：
1. 自持一把私钥（注册公钥到钱包服务，或钱包服务内置其公钥）
2. 按 [signed-request-v1.schema.json](signed-request-v1.schema.json) 签发请求
3. 用户确认后收到本地签名

即可接入，无需修改钱包服务。

### 防攻击要点

| 攻击 | 防护 |
|------|------|
| 重放 | `nonce` 一次性（平台侧原子消费）+ `expires_at` 时效 |
| 伪造调用 | `platform_signature` 验签（无平台私钥无法伪造） |
| 跨用户/跨地址 | 签名内容绑定 `user_id` + `wallet_address` |
| prompt injection | 钱包服务只签平台背书内容，自身不构造签名内容；弹窗展示 `display` 由用户确认 |

### 接入流程

```
平台: 签发 signed_request → 交用户 Agent
Agent: 调用钱包服务 MCP 工具 signed_request_sign(signed_request)
钱包服务: 验签 → 弹窗(display) → 用户允许 → 本地签名 → 返回
平台: 用 verify-sdk 验签 → 执行业务（提现放行/绑定确认）
```
