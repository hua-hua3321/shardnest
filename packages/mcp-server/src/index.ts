#!/usr/bin/env bun
/**
 * shardnest MCP 薄壳（无密钥）
 *
 * 架构：MCP 层只做「验平台背书 → 确认 → 转发签名守护」，
 * 私钥仅在签名瞬间于内存中重组并立即清零（复用 cli 的加密存储）。
 * 本层被攻破 = 拿不到任何持久化密钥材料。
 *
 * 环境变量：
 *   SHARDNEST_PLATFORM_ADDRESS  期望的平台背书地址（必填，验签用）
 *   SHARDNEST_HOME              钱包目录（默认 ~/.shardnest）
 */
import * as path from 'node:path'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { verifySignedRequest, type SignedRequest } from '@wallet-service/protocol'
import { initWallet, getAddress, restoreWallet, readRecoveryCodesFromFile, restoreFromMnemonic, exportMnemonicFromCodes, wipeWallet, WIPE_CONFIRM_PHRASE, listSavedFiles, getHomeDir, type WipeScope } from '@wallet-service/cli'
import { defaultApproval, type ApprovalHandler, WalletVault, consumeUnlockSession, consumePassphraseSession } from '@wallet-service/signer'

export const PLATFORM_ADDRESS = process.env.SHARDNEST_PLATFORM_ADDRESS ?? ''

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
  platformAddress: string = PLATFORM_ADDRESS,
) {
  const server = new McpServer({ name: 'shardnest', version: '0.3.0' })

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
      // 口令经本地口令令牌消费（CLI passphrase-token 生成；口令明文不进 LLM）
      let passphrase = await consumePassphraseSession(passphrase_token)
      let result: Awaited<ReturnType<typeof initWallet>>
      try {
        result = await initWallet(passphrase, email, generate_mnemonic === true)
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
        return { content: [{ type: 'text' as const, text: JSON.stringify({ error: 'USER_REJECTED' }) }] }
      }
      // 本地钱包必须存在（地址校验基准）
      let localAddress: string
      try {
        localAddress = await getAddress()
      } catch {
        return { content: [{ type: 'text' as const, text: JSON.stringify({ error: 'NO_WALLET' }) }] }
      }
      // 消费解锁令牌 → 组合私钥已在令牌会话中；导出助记词需要重新组合——改用恢复码文件
      // 简化：解锁令牌不承载组合私钥导出能力，助记词导出走「恢复码文件 + 本地解锁」的
      // 专用路径：读取本地恢复码文件（2 片）→ 组合 → 导出（地址交叉校验兜底）
      try {
        const codes = await readRecoveryCodesFromFile()
        if (codes.length < 2) {
          return { content: [{ type: 'text' as const, text: JSON.stringify({
            error: 'NEED_SECOND_RECOVERY_CODE',
            message: '本地恢复码仅 1 片（另一片已发邮箱）：请用 CLI `shardnest mnemonic-export`（设备片+恢复码模式）导出',
          }) }] }
        }
        const result = await exportMnemonicFromCodes(codes[0], codes[1])
        if (result.address.toLowerCase() !== localAddress.toLowerCase()) {
          return { content: [{ type: 'text' as const, text: JSON.stringify({ error: 'ADDRESS_MISMATCH' }) }] }
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
          return { content: [{ type: 'text' as const, text: JSON.stringify({
            error: 'NO_RECOVERY_FILE',
            message: '本地恢复码文件不存在（可能已 wipe）：请用 CLI `shardnest mnemonic-export`（设备片+恢复码模式）导出，或提供含恢复码的文件路径',
          }) }] }
        }
        return { content: [{ type: 'text' as const, text: JSON.stringify({ error: 'EXPORT_FAILED', message: (err as Error).message }) }] }
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
        return { content: [{ type: 'text' as const, text: JSON.stringify({ error: 'USER_REJECTED' }) }] }
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
        return { content: [{ type: 'text' as const, text: JSON.stringify({ error: 'WIPE_FAILED', message: (err as Error).message }) }] }
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
        return { content: [{ type: 'text' as const, text: 'NO_WALLET' }] }
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
      if (!platformAddress) {
        return { content: [{ type: 'text' as const, text: JSON.stringify({ error: 'PLATFORM_ADDRESS_NOT_CONFIGURED' }) }] }
      }
      const check = verifySignedRequest(signed_request, platformAddress)
      if (!check.ok) {
        return { content: [{ type: 'text' as const, text: JSON.stringify({ error: check.error }) }] }
      }
      const req = signed_request as SignedRequest

      // 纵深防御：wallet_address 必须与本地钱包一致（P1-3）
      let localAddress: string
      try {
        localAddress = await getAddress()
      } catch {
        return { content: [{ type: 'text' as const, text: JSON.stringify({ error: 'NO_WALLET' }) }] }
      }
      if (req.wallet_address.toLowerCase() !== localAddress.toLowerCase()) {
        return { content: [{ type: 'text' as const, text: JSON.stringify({ error: 'WALLET_ADDRESS_MISMATCH' }) }] }
      }

      // 闸门 2：用户确认（MCP 宿主注入；默认仅放行 sign_message）
      const approved = await approval({ action: req.action, display: req.display })
      if (!approved) {
        return { content: [{ type: 'text' as const, text: JSON.stringify({ error: 'USER_REJECTED' }) }] }
      }

      // 解锁令牌（本地 unlock 生成，口令/恢复码永不经 LLM；单次使用 + 5min TTL）
      let privateKey: Uint8Array
      try {
        privateKey = await consumeUnlockSession(unlock_token)
      } catch (err) {
        return { content: [{ type: 'text' as const, text: JSON.stringify({ error: 'UNLOCK_INVALID', message: (err as Error).message }) }] }
      }
      try {
        // 签名内容 = 平台背书的意图（intent_hash 由平台生成，本层不构造）
        const vault = new WalletVault()
        vault.unlockPrivateKey(privateKey)
        const sig = vault.signMessage(new TextEncoder().encode(`${req.action}:${req.intent_hash}`))
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
        const passphrase = await consumePassphraseSession(passphrase_token)
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
            return { content: [{ type: 'text' as const, text: JSON.stringify({
              error: 'NEED_SECOND_RECOVERY_CODE',
              message: '本地恢复码仅 1 片（另一片已发邮箱）：请用 CLI `shardnest restore` 交互恢复，或提供含第二片的恢复码文件路径',
            }) }] }
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
        return { content: [{ type: 'text' as const, text: JSON.stringify({ error: 'RESTORE_FAILED', message: (err as Error).message }) }] }
      }
    },
  )

  return server
}

// stdio 启动（直接运行 bin 时）
if (process.argv[1]?.endsWith('mcp-server/src/index.ts')) {
  const server = createShardnestServer()
  await server.connect(new StdioServerTransport())
}
