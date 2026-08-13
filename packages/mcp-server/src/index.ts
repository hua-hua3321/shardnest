#!/usr/bin/env bun
/**
 * shardnest MCP 薄壳（凭证不进 LLM；独立无密钥进程为路线图 P0-3）
 *
 * 架构：MCP 层只做「验平台背书 → 确认 → 转发签名守护」，
 * 私钥仅在签名瞬间于内存中重组并立即清零（复用 cli 的加密存储）。
 * 本层被攻破 = 拿不到任何持久化密钥材料。
 *
 * 环境变量：
 *   SHARDNEST_PLATFORM_ADDRESS  平台背书地址白名单（必填）：单个地址或逗号分隔多地址（多平台）
 *   SHARDNEST_PLATFORM_CONFIG   平台配置文件路径（可选）：JSON 数组 [{ name, address }]，与 env 合并
 *   SHARDNEST_HOME              钱包目录（默认 ~/.shardnest）
 */
import * as path from 'node:path'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { verifySignedRequest, walletSignMessage, type SignedRequest, type PlatformWhitelist } from '@wallet-services/protocol'
import { initWallet, getAddress, restoreWallet, readRecoveryCodesFromFile, restoreFromMnemonic, exportMnemonicFromCodes, wipeWallet, WIPE_CONFIRM_PHRASE, listSavedFiles, getHomeDir, type WipeScope } from '@wallet-services/cli'
import {defaultApproval, type ApprovalHandler, WalletVault, consumeUnlockSession, consumePassphraseSession, cleanupExpiredUnlockSessions} from '@wallet-services/signer'
import { ReplayGuard } from './replay-guard'

/** P1-3：钱包侧重放防护（模块级单例，跨 MCP server 实例共享） */
const replayGuard = new ReplayGuard()

/** 解析逗号分隔的地址白名单（env 通道）：空值/空串 → 空数组 */
export function parsePlatformAddresses(envValue: string | undefined): string[] {
  if (!envValue || envValue.trim() === '') return []
  return envValue.split(',').map((a) => a.trim()).filter((a) => a.length > 0)
}

/**
 * 多平台配置双通道加载（stdio 启动路径）：
 * 1. SHARDNEST_PLATFORM_ADDRESS：逗号分隔地址（简单场景，向后兼容）
 * 2. SHARDNEST_PLATFORM_CONFIG：JSON 文件 [{ name, address }]（复杂场景，可与 env 合并）
 * 文件缺失/格式非法 → 抛错拒绝启动（安全边界配置错误必须显式暴露，不静默降级）
 */
export async function loadPlatformAddresses(): Promise<string[]> {
  const fromEnv = parsePlatformAddresses(process.env.SHARDNEST_PLATFORM_ADDRESS)
  const configPath = process.env.SHARDNEST_PLATFORM_CONFIG?.trim()
  if (!configPath) return fromEnv
  const raw = await Bun.file(configPath).text().catch(() => {
    throw new Error(`SHARDNEST_PLATFORM_CONFIG 指向的文件不存在或不可读: ${configPath}`)
  })
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (err) {
    throw new Error(`SHARDNEST_PLATFORM_CONFIG 不是合法 JSON: ${(err as Error).message}`)
  }
  if (!Array.isArray(parsed)) throw new Error('SHARDNEST_PLATFORM_CONFIG 必须是 JSON 数组 [{ name, address }]')
  const fromFile: string[] = []
  for (const item of parsed) {
    if (typeof item !== 'object' || item === null || typeof (item as { address?: unknown }).address !== 'string') {
      throw new Error('SHARDNEST_PLATFORM_CONFIG 条目必须含字符串 address 字段')
    }
    fromFile.push((item as { address: string }).address.trim())
  }
  return [...fromEnv, ...fromFile]
}

/** 错误响应：isError=true 确保 LLM/客户端不会将安全拒绝误判为成功 */
function errResp(obj: Record<string, unknown>) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(obj) }], isError: true }
}

/** 路径约束：文件路径必须在钱包目录内（防穿越/符号链接逃逸到任意文件） */
async function assertSafePath(userPath: string): Promise<string> {
  const home = path.resolve(getHomeDir())
  const resolved = path.resolve(userPath)
  if (resolved !== home && !resolved.startsWith(home + path.sep)) {
    throw new Error('文件路径必须在钱包目录内')
  }
  try {
    const exists = await Bun.file(resolved).exists()
    if (exists) {
      const real = await (await import('node:fs/promises')).realpath(resolved)
      if (real !== home && !real.startsWith(home + path.sep)) {
        throw new Error('文件路径经过符号链接逃逸出钱包目录')
      }
    }
  } catch (err) {
    if ((err as Error).message.includes('钱包目录')) throw err
    // realpath 失败（文件不存在）时按 resolve 结果放行（后续 readFile 会 ENOENT）
  }
  return resolved
}

export function createShardnestServer(
  approval: ApprovalHandler = defaultApproval,
  platformAddresses: PlatformWhitelist = parsePlatformAddresses(process.env.SHARDNEST_PLATFORM_ADDRESS),
) {
  const server = new McpServer({ name: 'shardnest', version: '0.3.0' })

  // I6: 清理过期未消费的令牌会话（防堆积 + 减少侧信道）
  void cleanupExpiredUnlockSessions()

  // @ts-expect-error TS2589: sdk 1.x registerTool 泛型+zod 推导深度超限（运行时无影响）
  server.tool(
    'wallet_create',
    {
      passphrase_token: z.string(),
      email: z.string().email().optional(),
      // 可选：生成 24 词助记词（=完整私钥备份，可单独恢复；默认关闭）
      generate_mnemonic: z.boolean().optional(),
    },
    async ({ passphrase_token, email, generate_mnemonic }) => {
      // I11: 存在性检查前置——钱包已存在时不消费口令令牌（避免用户重新生成令牌）
      const existing = await getAddress().catch(() => null)
      if (existing) {
        return errResp({
          error: 'WALLET_EXISTS',
          address: existing,
          message: '钱包已存在；如需重建请先 wallet_wipe（需宿主 approval 确认），或用 CLI init 交互确认',
        })
      }
      // 口令经本地口令令牌消费（CLI passphrase-token 生成；口令明文不进 LLM）
      // P1-7: 口令令牌绑定操作——create 令牌只能用于建钱包
      let passphrase = await consumePassphraseSession(passphrase_token, 'create')
      let result: Awaited<ReturnType<typeof initWallet>>
      try {
        result = await initWallet(passphrase, email, generate_mnemonic === true, false) // W9: 已有钱包时拒绝（防静默覆盖）
      } finally {
        // JS string 不可变；置空引用提示 GC 尽早回收
        passphrase = ''
      }
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            address: result.address,
            // ⚠️ 恢复码/助记词不经 LLM：只返回本地文件路径（0600），用户自行查看保存
            recovery_codes_file: result.recoveryFile ?? null,
            mnemonic_file: result.mnemonicFile ?? null,
            backup_email: result.backupEmail ?? null,
            backup_status: result.backupStatus ?? null,
            warning: '恢复码已写入本地文件，请立即查看并妥善保存；如生成助记词，助记词=完整私钥（单点），请抄写后安全保管',
          }),
        }],
      }
    },
  )

  server.tool(
    'wallet_mnemonic_export',
    {
      // 无敏感参数：导出走本地恢复码文件（2 片）+ 地址交叉校验；
      // 助记词内容只写本地文件（0600），响应仅含文件路径
    },
    async () => {
      // 闸门：导出完整私钥（单点）——必须用户确认
      const approved = await approval({
        action: 'mnemonic_export',
        display: '⚠️ 导出 24 词助记词（=完整私钥，单点）：将完整私钥写入本地文件',
      })
      if (!approved) {
        return errResp({ error: 'USER_REJECTED' })
      }
      // 本地钱包必须存在（地址校验基准）
      let localAddress: string
      try {
        localAddress = await getAddress()
      } catch {
        return errResp({ error: 'NO_WALLET' })
      }
      // 消费解锁令牌 → 组合私钥已在令牌会话中；导出助记词需要重新组合——改用恢复码文件
      // 简化：解锁令牌不承载组合私钥导出能力，助记词导出走「恢复码文件 + 本地解锁」的
      // 专用路径：读取本地恢复码文件（2 片）→ 组合 → 导出（地址交叉校验兜底）
      try {
        const codes = await readRecoveryCodesFromFile()
        if (codes.length < 2) {
          return errResp({
            error: 'NEED_SECOND_RECOVERY_CODE',
            message: '本地恢复码仅 1 片（另一片已发邮箱）：请用 CLI `shardnest mnemonic-export`（设备片+恢复码模式）导出',
          })
        }
        const result = await exportMnemonicFromCodes(codes[0], codes[1])
        if (result.address.toLowerCase() !== localAddress.toLowerCase()) {
          return errResp({ error: 'ADDRESS_MISMATCH' })
        }
        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              address: result.address,
              // ⚠️ 助记词=完整私钥（单点）：只返回文件路径，内容不进 LLM
              mnemonic_file: result.mnemonicFile,
              warning: '助记词 = 完整私钥（单点），请抄写后安全保管；泄露即资金丢失',
            }),
          }],
        }
      } catch (err) {
        const e = err as NodeJS.ErrnoException
        if (e.code === 'ENOENT') {
          return errResp({
            error: 'NO_RECOVERY_FILE',
            message: '本地恢复码文件不存在（可能已 wipe）：请用 CLI `shardnest mnemonic-export`（设备片+恢复码模式）导出，或提供含恢复码的文件路径',
          })
        }
        return errResp({ error: 'EXPORT_FAILED', message: (err as Error).message })
      }
    },
  )

  server.tool(
    'wallet_wipe',
    {
      // 无敏感参数；高风险操作：必须通过 approval 用户确认闸门（默认拒绝）
      // scope: 'saved'=仅删需保存的明文备份（默认，保守）/ 'all'=删除本机全部密钥材料
      scope: z.enum(['saved', 'all']).optional(),
    },
    async ({ scope }) => {
      const wipeScope: WipeScope = scope ?? 'saved'
      const display = wipeScope === 'saved'
        ? '仅删除本机明文备份文件（恢复码/助记词，不可恢复；钱包保留）'
        : '删除本机全部密钥材料（不可恢复；需用保存的恢复码/助记词重建）'
      const approved = await approval({ action: 'wipe_wallet', display })
      if (!approved) {
        return errResp({ error: 'USER_REJECTED' })
      }
      try {
        const { removed } = await wipeWallet(WIPE_CONFIRM_PHRASE, wipeScope)
        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              removed_count: removed.length,
              removed: removed,
              warning: wipeScope === 'saved'
                ? '明文备份（恢复码/助记词）已彻底删除；钱包本体保留，口令解锁继续可用'
                : '本机密钥材料已彻底删除（不可恢复）；请确保已用离线保存的恢复码/助记词完成备份',
            }),
          }],
        }
      } catch (err) {
        return errResp({ error: 'WIPE_FAILED', message: (err as Error).message })
      }
    },
  )

  server.tool(
    'wallet_address',
    {},
    async () => {
      try {
        return { content: [{ type: 'text' as const, text: await getAddress() }] }
      } catch {
        return errResp({ error: 'NO_WALLET' })
      }
    },
  )

  // @ts-expect-error TS2589: sdk 1.x registerTool 泛型+zod 推导深度超限（运行时无影响）
  server.tool(
    'signed_request_sign',
    {
      signed_request: z.unknown(),
      unlock_token: z.string(),
    },
    async ({ signed_request, unlock_token }) => {
      // 闸门 1：平台背书验签（无平台私钥无法伪造；nonce/时效校验）
      // 白名单：单地址（向后兼容）或多平台地址数组
      const allowedList = Array.isArray(platformAddresses) ? platformAddresses : [platformAddresses]
      if (allowedList.length === 0) {
        return errResp({ error: 'PLATFORM_ADDRESS_NOT_CONFIGURED' })
      }
      const check = verifySignedRequest(signed_request, allowedList)
      if (!check.ok) {
        return errResp({ error: check.error })
      }
      const req = signed_request as SignedRequest
      // 验签恢复出的实际签发方地址（多平台下用于签名绑定 + 重放隔离，而非固定配置值）
      const verifiedPlatform = check.platformAddress ?? ''

      // P1-3：钱包侧重放防护（在消费解锁令牌前拦截，避免浪费一次性令牌）。
      // key 按平台地址隔离；同一 nonce 在有效期内第二次出现即视为重放。
      if (replayGuard.isReplay(`${verifiedPlatform.toLowerCase()}:${req.nonce}`, req.expires_at * 1000)) {
        return errResp({ error: 'NONCE_REUSED', message: '该 nonce 已被使用，疑似重放攻击' })
      }

      // 纵深防御：wallet_address 必须与本地钱包一致（P1-3）
      let localAddress: string
      try {
        localAddress = await getAddress()
      } catch {
        return errResp({ error: 'NO_WALLET' })
      }
      if (req.wallet_address.toLowerCase() !== localAddress.toLowerCase()) {
        return errResp({ error: 'WALLET_ADDRESS_MISMATCH' })
      }

      // 闸门 2：用户确认（MCP 宿主注入；默认仅放行 sign_message）
      const approved = await approval({ action: req.action, display: req.display })
      if (!approved) {
        return errResp({ error: 'USER_REJECTED' })
      }

      // 解锁令牌（本地 unlock 生成，口令/恢复码永不经 LLM；单次使用 + 5min TTL）
      let privateKey: Uint8Array
      try {
        privateKey = await consumeUnlockSession(unlock_token)
      } catch (err) {
        return errResp({ error: 'UNLOCK_INVALID', message: (err as Error).message })
      }
      try {
        // P1-6: 签名内容 = 域分离 + 请求上下文绑定（wallet_address/platform_address/
        // action/intent_hash/nonce/expires_at/user_id），与平台验签端共用 walletSignMessage
        const vault = new WalletVault()
        vault.unlockPrivateKey(privateKey)
        const sig = vault.signMessage(walletSignMessage({ ...req, platform_address: verifiedPlatform }))
        const address = vault.getAddress()
        vault.wipe()
        return { content: [{ type: 'text' as const, text: JSON.stringify({ address, signature: Buffer.from(sig).toString('hex') }) }] }
      } finally {
        privateKey.fill(0)
      }
    },
  )

  server.tool(
    'wallet_restore',
    {
      // 凭证隔离：恢复码/助记词经本地文件路径交付（内容不进 LLM）；口令经口令令牌
      recovery_file_path: z.string().optional(),
      mnemonic_file_path: z.string().optional(),
      passphrase_token: z.string(),
      expected_address: z.string().regex(/^0x[0-9a-fA-F]{40}$/, '期望地址格式无效').optional(),
      email: z.string().email().optional(),
    },
    async ({ recovery_file_path, mnemonic_file_path, passphrase_token, expected_address, email }) => {
      try {
        // P1-7: 口令令牌绑定操作——restore 令牌只能用于恢复
        const passphrase = await consumePassphraseSession(passphrase_token, 'restore')
        // 二选一：助记词文件（单份完整恢复）或恢复码文件（2-of-3 恢复）
        let result: Awaited<ReturnType<typeof restoreWallet>>
        if (mnemonic_file_path) {
          const safeMnemonicPath = await assertSafePath(mnemonic_file_path)
          const mnemonic = (await Bun.file(safeMnemonicPath).text())
            .split('\n').find((l) => l.trim().split(/\s+/).length >= 24)?.trim() ?? ''
          result = await restoreFromMnemonic(passphrase, mnemonic, expected_address, email)
        } else {
          const safePath = recovery_file_path ? await assertSafePath(recovery_file_path) : undefined
          const codes = await readRecoveryCodesFromFile(safePath)
          if (codes.length < 2) {
            return errResp({
              error: 'NEED_SECOND_RECOVERY_CODE',
              message: '本地恢复码仅 1 片（另一片已发邮箱）：请用 CLI `shardnest restore` 交互恢复，或提供含第二片的恢复码文件路径',
            })
          }
          result = await restoreWallet(
            passphrase,
            [codes[0], codes[1]],
            expected_address,
            email,
          )
        }
        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              address: result.address,
              // ⚠️ 新恢复码不经 LLM：只返回本地文件路径
              recovery_codes_file: result.recoveryFile ?? null,
              backup_email: result.backupEmail ?? null,
              backup_status: result.backupStatus ?? null,
              note: result.note ?? null,
              warning: '新恢复码已写入本地文件，请立即查看并妥善保存；旧恢复码请作废销毁',
            }),
          }],
        }
      } catch (err) {
        return errResp({ error: 'RESTORE_FAILED', message: (err as Error).message })
      }
    },
  )

  return server
}

// stdio 启动（直接运行本文件时——兼容源码 src/index.ts、构建产物 dist/index.js
// 及 npm 安装后的任意路径；被测试/其他模块 import 时 argv[1] 是调用方，不启动）
if (process.argv[1]) {
  const { realpath } = await import('node:fs/promises')
  const { fileURLToPath } = await import('node:url')
  const self = await realpath(fileURLToPath(import.meta.url))
  const entry = await realpath(process.argv[1]).catch(() => process.argv[1] as string)
  if (entry === self) {
    // 多平台配置双通道：env 逗号分隔 + JSON 配置文件；启动时校验，失败即拒绝启动
    const addresses = await loadPlatformAddresses()
    const server = createShardnestServer(defaultApproval, addresses)
    await server.connect(new StdioServerTransport())
  }
}
