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
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { verifySignedRequest, type SignedRequest } from '@wallet-service/protocol'
import { initWallet, getAddress, restoreWallet, readRecoveryCodesFromFile } from '@wallet-service/cli'
import { defaultApproval, type ApprovalHandler, WalletVault, consumeUnlockSession } from '@wallet-service/signer'

export const PLATFORM_ADDRESS = process.env.SHARDNEST_PLATFORM_ADDRESS ?? ''

export function createShardnestServer(
  approval: ApprovalHandler = defaultApproval,
  platformAddress: string = PLATFORM_ADDRESS,
) {
  const server = new McpServer({ name: 'shardnest', version: '0.3.0' })

  server.tool(
    'wallet_create',
    { passphrase: z.string().min(12), email: z.string().email().optional() },
    async ({ passphrase, email }) => {
      const result = await initWallet(passphrase, email)
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            address: result.address,
            // ⚠️ 恢复码不经 LLM：只返回本地文件路径（0600），用户自行查看保存
            recovery_codes_file: result.recoveryFile ?? null,
            backup_email: result.backupEmail ?? null,
            backup_status: result.backupStatus ?? null,
            warning: '恢复码已写入本地文件，请立即查看并妥善保存；如提供邮箱，备份分片已发送',
          }),
        }],
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
      // 凭证隔离：恢复码经本地文件路径交付（内容不进 LLM）；口令为新设口令（无本地文件不可用）
      recovery_file_path: z.string().optional(),
      passphrase: z.string().min(12),
      expected_address: z.string().regex(/^0x[0-9a-fA-F]{40}$/, '期望地址格式无效').optional(),
      email: z.string().email().optional(),
    },
    async ({ recovery_file_path, passphrase, expected_address, email }) => {
      try {
        const codes = await readRecoveryCodesFromFile(recovery_file_path)
        const result = await restoreWallet(
          passphrase,
          [codes[0], codes[1]],
          expected_address,
          email,
        )
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
