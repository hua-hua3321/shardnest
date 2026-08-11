---
title: shardnest 使用教程
date: 2026-08-09
status: active
last_reviewed: 2026-08-09
tags: ['wallet', 'tutorial', 'CLI', 'MCP', 'recovery', 'mnemonic']
---

# shardnest 使用教程（端到端）

> 本教程带您完整走一遍钱包生命周期：**创建 -> 备份 -> 日常使用 -> 恢复 -> 彻底删除**。
> 所有命令均为交互式（口令与恢复码掩码输入，不会出现在终端记录中）。

---

## 场景 A：创建钱包（3 分钟）

### 1. 安装

```bash
git clone https://github.com/hua-hua3321/shardnest.git
cd shardnest && bun install
```

### 2. 初始化

```bash
bun packages/cli/src/index.ts init
```

交互流程：

```
设置口令（>=12 位，用于加密设备分片）: ********          <- 至少 12 位，建议混合大小写/数字/符号
邮箱（可选，自动发送备份分片...）: user@example.com     <- 可选；提供后片3自动发到邮箱（三处分布）
是否生成 24 词助记词备份？（默认不生成）[y/N]: n         <- 默认否；专业用户可 y（见下文说明）
✅ 钱包已创建
地址: 0xAFD0...
⚠️  恢复码（请立即保存，丢失后设备损坏将无法找回）:
  sn1-2-<64位hex>-<8位crc>
  sn1-3-<64位hex>-<8位crc>
```

**创建后立即完成 3 件事**：
1. **保存恢复码**——`recovery-codes.txt` 已写入 `~/.shardnest/`，**请勿手抄**（64 位 hex），转移文件即可
2. **检查邮箱**——若提供了邮箱，片3 已发送（本地仅存 1 片=真正三处分布）
3. **确认备份分布**——无邮箱时本地存 2 片，会显示显著警告，请把 1 片离线保存

> **助记词（可选）**：生成 24 词助记词 = 标准 BIP-39/44（可导入 MetaMask 恢复同一地址）。
> 但助记词 = 完整私钥（单点）：泄露即资金丢失。普通用户建议不生成；专业/高资产用户
> 生成后请抄写离线保管，并执行 `wipe`（范围 1）删除本机明文副本。

### 3. 查看地址

```bash
bun packages/cli/src/index.ts address
```

---

## 场景 B：日常签名（CLI 与 MCP 双路径）

### 路径 1：CLI 直接签名

```bash
bun packages/cli/src/index.ts sign "hello shardnest"
# 口令 + 恢复码（掩码输入）-> 输出 { address, signature }
```

### 路径 2：MCP（Agent 场景，凭证隔离）

1. **生成口令令牌**（口令明文不进 LLM）：

```bash
bun packages/cli/src/index.ts passphrase-token
# 输入口令 -> 输出令牌（5 分钟有效、单次使用）
```

2. **创建钱包**（MCP `wallet_create`，参数 `passphrase_token`）
3. **生成解锁令牌**（签名前）：

```bash
bun packages/cli/src/index.ts unlock
# 口令 + 恢复码 -> 输出解锁令牌（5 分钟有效、单次使用）
```

4. **签名**（MCP `signed_request_sign`，参数 `signed_request` + `unlock_token`）：
   双闸门 = 平台背书验签 + 宿主 approval 确认，签名内容为 `action:intent_hash`

> 恢复码来源引导：`unlock`/`sign` 前会按本地存储状态提示第二因素应来自哪里
> （邮箱片3 / 离线副本），请遵循提示选择来源。

---

## 场景 C：恢复钱包

### 方式 1：2 个恢复码（新设备/口令丢失）

```bash
bun packages/cli/src/index.ts restore
# 新口令 -> 恢复码 1 -> 恢复码 2 -> 期望地址（可选，强烈建议）-> 邮箱（可选）
# ✅ 钱包已恢复（地址交叉校验通过）
```

### 方式 2：24 词助记词单独恢复

```bash
bun packages/cli/src/index.ts restore-mnemonic
# 新口令 -> 24 词（空格分隔，校验和验证）-> 期望地址（可选）-> 邮箱（可选）
```

> 旧恢复码/旧邮箱备份片仍可重组同一私钥——恢复后请**作废销毁旧载体**。

### 方式 3：任意 2 片导出助记词（备份用）

```bash
bun packages/cli/src/index.ts mnemonic-export
# 模式 a) 设备片+恢复码（需口令） 或 b) 两个恢复码
# -> 写入 mnemonic.txt（24 词 = 完整私钥，请抄写后安全保管）
```

---

## 场景 D：彻底删除（不可恢复）

```bash
bun packages/cli/src/index.ts wipe
```

```
📌 请选择删除范围：
  1) 仅删除「需用户保存」的明文备份（恢复码/助记词）——钱包保留（推荐）
  2) 删除本机所有相关内容（钱包也删）
选择 [1/2]: 1
📄 将删除以下文件（覆写 3 遍，不可恢复）:
  - recovery-codes.txt
  - mnemonic.txt
📌 执行前请确认：
    1. 恢复码/助记词已保存到安全位置——这是唯一恢复途径
    2. 业务平台绑定等操作已处理完毕
请输入确认短语「PERMANENT DELETE」: ********
✅ 已彻底删除 2 个文件
```

> 删除前请务必确认恢复码/助记词已安全保存——删除后本机无任何恢复途径。

---

## 语言切换

CLI 按系统语言自动切换中英文（`zh*` -> 中文，其余 -> 英文）。
显式覆盖：`SHARDNEST_LANG=zh|en`。

```bash
SHARDNEST_LANG=en bun packages/cli/src/index.ts init   # 强制英文
```

---

## 故障排查

| 现象 | 原因 | 处理 |
|------|------|------|
| 「口令错误，或设备分片已损坏」 | 口令输错，或设备分片损坏 | 核对口令重试；损坏则用恢复码 `restore` |
| 「钱包已存在」 | 重复 init（防静默覆盖，W9） | 先 `wipe` 或 `restore`，或 CLI 交互确认后重建 |
| 「恢复码校验失败」 | 恢复码抄错/损坏（32 位 CRC 拦截） | 重新核对恢复码 |
| 「组合出的地址与本地钱包不一致」 | 恢复码输错 | 核对恢复码，确认来自同一钱包 |
| 「助记词无效」 | 助记词抄错/词表不符（校验和拦截） | 重新核对 24 词 |
| 默认 approval 拒绝 wipe | MCP 路径需宿主注入 approval（OS 弹窗） | 宿主配置 approval handler；CLI 路径不受影响 |

---

## 参考

- 完整命令表：[README.zh-CN.md](../README.zh-CN.md)
- 安全模型：[SECURITY.md](SECURITY.md)
- 修改说明：[CHANGELOG.md](CHANGELOG.md)
- 开发指南：[DEVELOPMENT.md](DEVELOPMENT.md)
- 第三方接入：[INTEGRATION.md](INTEGRATION.md)
