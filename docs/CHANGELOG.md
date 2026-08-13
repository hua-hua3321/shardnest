---
title: shardnest 修改说明（CHANGELOG）
date: 2026-08-09
status: active
last_reviewed: 2026-08-09
tags: ['changelog', 'release-notes', 'history']
---

# 修改说明（CHANGELOG）

> 按里程碑归纳。每个提交均可 `git log --oneline` 追溯。

## v0.4.x — 多平台接入（当前）

### 2026-08-12 · 多平台白名单 + 接入引导
- **多平台背书白名单**：`verifySignedRequest` 接受地址数组（单地址向后兼容），验签恢复实际签发方地址返回 `platformAddress`
- **配置双通道**：`SHARDNEST_PLATFORM_ADDRESS` 支持逗号分隔多地址（简单场景）；新增 `SHARDNEST_PLATFORM_CONFIG`（JSON 数组 `[{ name, address }]`，复杂场景，与 env 合并）；文件缺失/格式非法 → 拒绝启动（安全边界不静默降级）
- **签名绑定实际签发方**：MCP 签名路径用验签恢复出的平台地址（而非固定配置值）做 `walletSignMessage` 绑定 + ReplayGuard 隔离——多平台下签名与真实平台一一对应
- **`init-platform` 命令**：一条命令生成平台背书密钥对 + 输出全部配置片段（env/多平台逗号拼接/platforms.json 条目）
- **`.env.example`**：全部 `SHARDNEST_*` 变量模板（含多平台注释），可直接复制
- 新增 16 条测试（protocol 多平台白名单 5 条 + MCP 多平台签名/配置解析 7 条 + CLI 密钥对 1 条等）

## v0.3.x — 密码学现代化

### 2026-08-09 · 第九轮 polish
- **I18**：`getAddress` 校验 metadata（损坏 → 干净拒绝而非裸 TypeError）
- **I19**：`SHARDNEST_HOME` 空串回退默认目录（防钱包落到 cwd）
- **I20**：随机源环境假设注释；**I21**：MetaMask 实测留待接入平台前

### 2026-08-09 · 第八轮测试固化
- **W15**：BIP-44 标准地址固化测试（全零熵助记词 → `0xF278cF59...`，双路径交叉验证，MetaMask 兼容性守护）
- **I17**：v1 真实钱包（2^16 加密）解密夹具测试（C1 回归守护）

### 2026-08-09 · 三视角审查修复
- **C1**：`decryptShare` v1 回退用历史参数（LEGACY 2^16）——真实 v1 钱包不被锁出
- **W2**：移除 `WalletVault.unlock(shares)` 死 API（O4A 后语义失效）；测试重写
- **W3**：`createWalletFromEntropy` 早抛路径补熵/分片清零（不变式 5 全路径）
- **W4**：恢复码 CRC 双宽兼容（旧 8 位码仍放行）
- **W5**：restore-mnemonic 提示旧格式助记词语义变化（诚实标注）
- **W6**：canonicalBytes 布局注释修正；**W7**：@scure/bip32 精确锁版
- **W1**：文档滞后全面同步（AGENTS/SECURITY/keys/shamir）

### 2026-08-09 · 优化批次（O1-O6）
- **O1**：KDF 参数（scrypt N/r/p）随密文持久化（device-share.json v2）——未来参数升级不破坏旧钱包
- **O2**：scrypt N 2^16 → **2^17**（OWASP 2023 下限，128MB）
- **O3**：恢复码 CRC 8 → **32 位**（漏检率 1/2^32）
- **O4A**：**BIP-39/44 标准化**（熵为根：分片熵 → m/44'/60'/0'/0/0 派生私钥）——助记词可导入 MetaMask 恢复同一地址
- **O4B**：助记词引导文案（随 O4A 更新为标准兼容说明）
- **O5**：canonicalString(JSON) → **canonicalBytes**（length-prefixed 二进制，消除跨语言陷阱）
- **W14**：BIP-39 seed 纳入不变式 5 内存清零；**S1**：文档同步

## v0.2.x — 安全加固

### 2026-08-09 · 九轮审查（W1-W13 修复）
- **C1**：init/restore 失败回滚补 recovery/mnemonic 文件（原子性完整）
- **W1**：wipe 确认提示乱码修复；**W2**：approval 类型联合补全
- **W6-W8**：不变式 5 内存清零全覆盖（分片/私钥/seed）
- **W9**：init 防静默覆盖（force 参数 + CLI 确认 + MCP 前置检查）
- **W12**：默认 approval 拒绝 wipe（默认应安全）
- **W13**：canonical Unicode 陷阱（O5 根治）
- **I1**：tsc 修复（@types/bun）；**I2-I10**：令牌文案/口令反馈/来源引导等

### 2026-08-09 · 功能增强
- 邮箱备份分片（init 提供邮箱自动发送片3）
- 可选 24 词助记词（默认关闭，引导好坏处）
- 任意 2 片导出助记词（mnemonic-export）
- wipe 双模式（saved/all + 文件清单 + 确认短语）
- CLI 中英文（按系统语言自动切换，SHARDNEST_LANG 覆盖）
- 恢复码来源引导（按存储策略提示第二因素来源）

## v0.1.x — 基础能力

- M3 协议层：signed_request v1（平台背书签发/验签）
- MCP 薄壳：6 工具（wallet_create/address/mnemonic_export/signed_request_sign/restore/wipe）
- 凭证隔离三通道：passphrase_token / unlock_token / 文件路径
- 双闸门：平台背书验签 + approval 确认
- SSS 2-of-3 分片 + EIP-191 签名 + verify-sdk

---

## 发布流程

1. 跑全量测试：`for p in core signer cli verify-sdk protocol mcp-server; do (cd packages/$p && bun test); done`
2. 类型检查：`bunx tsc --noEmit`（必须 0 错误）
3. 更新本文件 + SECURITY.md 修复记录
4. 提交 + 推送 GitHub（shardnest 独立仓库，独立发版）
