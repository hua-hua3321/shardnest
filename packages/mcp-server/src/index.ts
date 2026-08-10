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
import { initWallet, getAddress, restoreWallet, signMessage } from '@wallet-service/cli'
import { defaultApproval, type ApprovalHandler } from '@wallet-service/signer'

export const PLATFORM_ADDRESS = process.env.SHARDNEST_PLATFORM_ADDRESS ?? ''

export function createShardnestServer(
  approval: ApprovalHandler = defaultApproval,
  platformAddress: string = PLATFORM_ADDRESS,
) {
  const server = new McpServer({ name: 'shardnest', version: '0.3.0' })

  server.tool(
    'wallet_create',
    { passphrase: z.string().min(8) },
    async ({ passphrase }) => {
      const result = await initWallet(passphrase)
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            address: result.address,
            recovery_codes: result.recoveryCodes,
            warning: '请立即保存恢复码；丢失后设备损坏将无法找回',
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
      passphrase: z.string(),
      recovery_code: z.string(),
    },
    async ({ signed_request, passphrase, recovery_code }) => {
      // 闸门 1：平台背书验签（无平台私钥无法伪造；nonce/时效校验）
      if (!platformAddress) {
        return { content: [{ type: 'text' as const, text: JSON.stringify({ error: 'PLATFORM_ADDRESS_NOT_CONFIGURED' }) }] }
      }
      const check = verifySignedRequest(signed_request, platformAddress)
      if (!check.ok) {
        return { content: [{ type: 'text' as const, text: JSON.stringify({ error: check.error }) }] }
      }
      const req = signed_request as SignedRequest

      // 闸门 2：用户确认（MCP 宿主注入；默认仅放行 sign_message）
      const approved = await approval({ action: req.action, display: req.display })
      if (!approved) {
        return { content: [{ type: 'text' as const, text: JSON.stringify({ error: 'USER_REJECTED' }) }] }
      }

      // 签名内容 = 平台背书的意图（intent_hash 由平台生成，本层不构造）
      const out = await signMessage(passphrase, recovery_code, `${req.action}:${req.intent_hash}`)
      return { content: [{ type: 'text' as const, text: out }] }
    },
  )

  server.tool(
    'wallet_restore',
    { passphrase: z.string().min(8), recovery_code_1: z.string(), recovery_code_2: z.string() },
    async ({ passphrase, recovery_code_1, recovery_code_2 }) => {
      const result = await restoreWallet(passphrase, [recovery_code_1, recovery_code_2])
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            address: result.address,
            recovery_codes: result.recoveryCodes,
            warning: '旧恢复码请作废销毁（旧分片集仍可重组同一私钥）',
          }),
        }],
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
