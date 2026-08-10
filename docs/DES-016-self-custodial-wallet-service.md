---
title: 独立开源钱包服务项目规划
doc_id: DES-016
type: design
status: draft
version: 0.1
owner: 创始人
last_reviewed: 2026-08-09
updated: 2026-08-09
tags: ['钱包', '开源', '独立项目', 'MCP', 'SSS', '自托管', '验签协议']
related: ['DES-015', 'RES-005']
---

# 独立开源钱包服务项目规划

> **性质：** 独立项目规划（draft）。本项目与 EnvoyTask **完全独立**：
> 独立仓库、独立发版、独立治理，仅通过公开协议（signed_request）与任何平台弱耦合。
> 本规划文档暂存于 EnvoyTask 文档库仅用于记录决策，项目启动后迁移至新仓库。

---

## 1. 项目定位

**一句话：** 开源、自托管、非托管的钱包基础设施服务——钱包生成、密钥分片、恢复、验签，以 MCP server / CLI / SDK 多形态交付，任何平台（不限于 EnvoyTask）只要符合公开协议即可接入。

| 维度 | 定位 |
|------|------|
| 生态位 | 对标 Web3Auth / Lit Protocol，但差异化：**开源 + 用户本地自托管 + 通用背书协议** |
| 责任模型 | 钱包与密钥的保存责任 100% 归用户（self-custody），服务方零密钥材料 |
| 交付形态 | MCP server（Agent 生态主通道）+ CLI（人工场景）+ SDK（平台集成） |
| 开源策略 | 独立仓库开源（MIT/Apache-2.0），先受限发布后全开源 |

## 2. 为什么独立（决策背景）

1. **责任彻底分离**：钱包责任归用户，业务平台零密钥材料——合规上最干净的「非托管」定论
2. **通用基础设施**：任何平台（任务撮合、电商、社交）都可接入，复用同一钱包服务
3. **生态复用**：开源可审计、可演进、可建立社区（对标 Phantom MCP / Coinbase Payments MCP 的生态位，但坚持自托管）
4. **与 EnvoyTask 解耦**：互不干涉、独立发版、独立许可证，EnvoyTask 只是第一个接入方

## 3. 核心能力

| 能力 | 说明 |
|------|------|
| 钱包生成 | CSPRNG 随机私钥（口令不参与私钥，仅作加密钥匙） |
| 私钥分片 | Shamir SSS 2-of-3（任意 2 片可重组） |
| 分片存储 | 片①设备（Keychain/Keystore）；片②口令加密→用户云盘/自管；片③恢复码/纸质 |
| 签名 | 验平台背书 → 用户确认 → 本地签名（双闸门） |
| 恢复 | 口令遗忘 / 设备丢失 / 分片重组（客户端完成） |
| reshare | 整体重分片 + 旧载体物理清理（两阶段提交） |
| 验签 SDK | 平台侧集成用（verifyMessage 封装，verify-only） |

## 4. 架构设计

### 4.1 薄壳 MCP + 签名守护进程（防恶意调用）

```
┌─ MCP server（无密钥薄壳）──────────────────┐
│ 验平台背书 → 转发请求 → 返回结果（可被攻破） │
└──────────────┬─────────────────────────────┘
               │ 本地 IPC（Unix socket / 随机端口 + token）
┌──────────────▼─────────────────────────────┐
│ 签名守护进程（唯一持钥者）                    │
│ Keychain/Keystore + OS 弹窗确认 + 用完清零    │
└─────────────────────────────────────────────┘
```

### 4.2 双闸门（防 prompt injection / 本地恶意程序）

| 闸门 | 机制 | 防什么 |
|------|------|--------|
| 闸门 1：平台背书 | 签名请求必须带平台私钥签发的 `signed_request`（含 intent_hash/nonce/user_id/address/expires_at），技能包内置平台公钥验签 | 伪造调用、重放 |
| 闸门 2：用户确认 | 验签通过后 OS 级弹窗显示可读摘要，用户点【允许】才签名；高价值操作追加二次口令 | 静默签名、被诱导签名 |

### 4.3 口令输入隔离（防聊天记录泄露）

- 口令只在签名守护进程的本地弹窗输入——**不进入 LLM 上下文、不进入聊天记录、不上传网络**
- 聊天通道只承载操作意图，不承载任何秘密
- 日常操作免密（Keychain 生物识别），口令仅用于新设备绑定/找回后重加密

## 5. 公开协议：signed_request v1（与平台唯一耦合点）

### 5.1 请求格式

```jsonc
{
  "v": 1,
  "action": "sign_message | sign_tx | bind_wallet | withdraw_confirm",
  "intent_hash": "0x…",          // 平台对意图内容(如提现明细)的哈希
  "display": "向 0x… 提现 50 USDC", // 弹窗展示的可读摘要
  "user_id": "platform-user-123",
  "wallet_address": "0x…",
  "nonce": "一次性随机值",
  "expires_at": 1710000000,
  "platform_signature": "0x…"     // 平台私钥签名以上字段
}
```

### 5.2 接入流程（任意平台）

1. 平台注册公钥 → 获得签发能力（自持私钥）
2. 平台按规范签发 `signed_request` → 交给用户的钱包服务
3. 钱包服务验签 → 弹窗确认 → 本地签名 → 回传
4. 平台用验签 SDK 验证签名 → 执行业务

### 5.3 防攻击要点

- nonce 一次性防重放；`expires_at` 限时效；签名内容绑定 user_id + wallet_address 防跨用户/跨地址

## 6. 技术选型（全部复用成熟组件）

| 组件 | 选择 | 理由 |
|------|------|------|
| 语言/运行时 | TypeScript + Bun | 与生态一致、单二进制友好 |
| MCP | @modelcontextprotocol/sdk | 官方 SDK |
| 密码学 | noble-curves / noble-hashes / viem | 审计级、纯 TS |
| SSS | secrets.js-grempe（或自研 GF(256) + 向量测试） | 成熟实现 |
| 本地存储 | Keychain / Android Keystore / WebCrypto(IndexedDB) | 系统级保护 |
| 发布 | npm 包 + GitHub Release + GPG 签名 | 供应链防护 |

## 7. 独立仓库结构（规划）

```
wallet-service/                    ← 独立 git 仓库（与 EnvoyTask 无任何代码共享）
├── packages/
│   ├── core/                      # 密钥生成、SSS 分片、恢复、reshare（纯逻辑，无 IO）
│   ├── signer/                    # 签名守护进程（持钥、弹窗、IPC）
│   ├── mcp-server/                # MCP 薄壳（无密钥）
│   ├── cli/                       # 命令行形态（人工场景）
│   └── verify-sdk/                # 平台侧验签 SDK（verify-only，无密钥逻辑）
├── protocol/                      # signed_request v1 规范（JSON Schema + 文档）
├── tests/                         # 向量测试、分片恢复、并发、攻击场景
├── docs/                          # 安全模型、接入指南、审计报告
└── LICENSE / README.md
```

## 8. 安全模型与边界

| 威胁 | 防护 | 残余风险 |
|------|------|---------|
| 服务器/服务方被黑 | 零密钥材料 | 无 |
| 用户设备被控 | Keychain + 弹窗确认 | 设备完全沦陷时无法防御（与硬件钱包同级） |
| prompt injection | 平台背书 + 弹窗 | 用户误点确认（二次口令缓解） |
| 分片泄露（单点） | 2-of-3 门限 | 需 2 片同时泄露 |
| 口令+设备双丢 | — | **不可恢复（合理边界，注册时披露）** |

## 9. Roadmap

| 阶段 | 内容 |
|------|------|
| M1 核心 | core（生成/分片/恢复/reshare）+ 向量测试 |
| M2 形态 | signer 守护进程 + CLI + verify-sdk |
| M3 协议 | signed_request v1 + MCP 薄壳 + 双闸门 |
| M4 开源 | 独立仓库公开发布 + 文档 + 审计（先受限后全开源） |
| M5 生态 | 接入 EnvoyTask（第一个接入方）+ 输出接入指南 |

## 10. 与 EnvoyTask 的接入关系（仅协议耦合）

```
用户 Agent 环境：
├── MCP server ① EnvoyTask 平台    （业务 + 绑定 + 签发 signed_request）
├── MCP server ② wallet-service    （独立开源，签名/分片/恢复）
└── 无直接调用：平台签请求 → Agent 转交钱包服务 → 签名回传
```

- EnvoyTask 平台侧改造：退役 aa-wallet.ts（派生/预测），新增 wallet-binding（绑定/换绑/验签），提现改为验签确认
- `agents` 表存 `wallet_address` + 公钥
- 两个 MCP server 互不干涉，仅通过 signed_request 协议交互

---

## 附：与现有文档的关系

- [DES-015](client-side-wallet-creation.md)：钱包方案思路演进稿（本规划为最终定稿方向，DES-015 相关章节可标记 superseded）
- [RES-005](../05-research/wallet-key-sharding-recovery.md)：成熟方案调研（SSS/TSS/社交恢复对比，支撑本规划技术选型）
