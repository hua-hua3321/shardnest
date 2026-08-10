import { describe, it, expect, beforeEach } from 'bun:test'
import { promises as fs } from 'node:fs'
import * as path from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { createShardnestServer } from '../src/index'
import { issueSignedRequest } from '@wallet-service/protocol'
import { generatePrivateKey, privateKeyToAddress } from '@wallet-service/core'
import { recoverSigner } from '@wallet-service/verify-sdk'
import { createUnlockToken } from '@wallet-service/cli'

const TEST_HOME = path.join(process.cwd(), '.test-shardnest-mcp')

beforeEach(async () => {
  await fs.rm(TEST_HOME, { recursive: true, force: true })
  process.env.SHARDNEST_HOME = TEST_HOME
})

const platformPriv = generatePrivateKey()
const platformAddr = privateKeyToAddress(platformPriv)
const PASSPHRASE = 'mcp-passphrase-123!'

async function connect(approval?: (req: { action: string; display: string }) => boolean) {
  const server = createShardnestServer(
    approval ?? (() => true),
    platformAddr,
  )
  const client = new Client({ name: 'test-client', version: '1.0.0' })
  const [c2s, s2c] = InMemoryTransport.createLinkedPair()
  await Promise.all([server.connect(s2c), client.connect(c2s)])
  return client
}

describe('shardnest MCP 薄壳', () => {
  it('注册 4 个工具', async () => {
    const client = await connect()
    const tools = await client.listTools()
    const names = tools.tools.map((t) => t.name).sort()
    expect(names).toEqual(['signed_request_sign', 'wallet_address', 'wallet_create', 'wallet_restore'])
  })

  it('wallet_create → 返回地址 + 恢复码', async () => {
    const client = await connect()
    const res = await client.callTool({ name: 'wallet_create', arguments: { passphrase: PASSPHRASE } })
    const text = res.content[0] as { type: string; text: string }
    const data = JSON.parse(text.text)
    expect(data.address).toMatch(/^0x[0-9a-fA-F]{40}$/)
    expect(data.recovery_codes.length).toBe(2)
  })

  it('wallet_create 带 email → 返回 backup 状态（未配置 SMTP = skipped）', async () => {
    const client = await connect()
    const res = await client.callTool({
      name: 'wallet_create',
      arguments: { passphrase: PASSPHRASE, email: 'user@example.com' },
    })
    const data = JSON.parse((res.content[0] as { text: string }).text)
    expect(data.backup_email).toBe('user@example.com')
    expect(data.backup_status).toBe('skipped')
  })

  it('signed_request_sign：平台背书 → 确认 → 返回可验签签名', async () => {
    const client = await connect()
    // 1. 创建钱包（拿地址 + 恢复码）
    const created = JSON.parse(((await client.callTool({ name: 'wallet_create', arguments: { passphrase: PASSPHRASE } })).content[0] as { text: string }).text)
    // 2. 平台签发背书请求（钱包地址绑定）
    const req = issueSignedRequest({
      action: 'bind_wallet',
      intentHash: '0x' + 'cd'.repeat(32),
      display: '绑定钱包到 envoytask 平台',
      userId: 'user-42',
      walletAddress: created.address,
      nonce: 'nonce-mcp-00000001',
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    }, platformPriv)
    // 3. 本地解锁（口令+恢复码在本地生成令牌，不经 LLM）
    const token = await createUnlockToken(PASSPHRASE, created.recovery_codes[0])
    // 4. 签名（验背书 → 地址校验 → 确认 → 令牌消费 → 本地签名）
    const signRes = await client.callTool({
      name: 'signed_request_sign',
      arguments: { signed_request: req, unlock_token: token },
    })
    const out = JSON.parse((signRes.content[0] as { text: string }).text)
    expect(out.address).toBe(created.address)
    // 5. 验签还原同一地址（平台侧可验证）
    const sig = Uint8Array.from(Buffer.from(out.signature, 'hex'))
    const recovered = recoverSigner(`bind_wallet:${req.intent_hash}`, sig)
    expect(recovered.toLowerCase()).toBe(created.address.toLowerCase())
  })

  it('wallet_address 与本地不一致 → WALLET_ADDRESS_MISMATCH 拒绝（纵深防御）', async () => {
    const client = await connect()
    const created = JSON.parse(((await client.callTool({ name: 'wallet_create', arguments: { passphrase: PASSPHRASE } })).content[0] as { text: string }).text)
    const token = await createUnlockToken(PASSPHRASE, created.recovery_codes[0])
    const req = issueSignedRequest({
      action: 'bind_wallet',
      intentHash: '0x' + 'ab'.repeat(32),
      display: '绑定其他钱包地址',
      userId: 'user-42',
      walletAddress: '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf', // 与本地不同
      nonce: 'nonce-mcp-00000009',
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    }, platformPriv)
    const res = await client.callTool({
      name: 'signed_request_sign',
      arguments: { signed_request: req, unlock_token: token },
    })
    const out = JSON.parse((res.content[0] as { text: string }).text)
    expect(out.error).toBe('WALLET_ADDRESS_MISMATCH')
  })

  it('无效解锁令牌 → UNLOCK_INVALID（单次使用 + 过期防护）', async () => {
    const client = await connect()
    const created = JSON.parse(((await client.callTool({ name: 'wallet_create', arguments: { passphrase: PASSPHRASE } })).content[0] as { text: string }).text)
    const req = issueSignedRequest({
      action: 'bind_wallet',
      intentHash: '0x' + 'cd'.repeat(32),
      display: '绑定钱包',
      userId: 'user-42',
      walletAddress: created.address,
      nonce: 'nonce-mcp-00000010',
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    }, platformPriv)
    const res = await client.callTool({
      name: 'signed_request_sign',
      arguments: { signed_request: req, unlock_token: '0'.repeat(64) },
    })
    const out = JSON.parse((res.content[0] as { text: string }).text)
    expect(out.error).toBe('UNLOCK_INVALID')
  })

  it('伪造背书（非平台签发）→ BAD_SIGNATURE 拒绝', async () => {
    const client = await connect()
    const fake = generatePrivateKey()
    const created = JSON.parse(((await client.callTool({ name: 'wallet_create', arguments: { passphrase: PASSPHRASE } })).content[0] as { text: string }).text)
    const req = issueSignedRequest({
      action: 'bind_wallet',
      intentHash: '0x' + 'ef'.repeat(32),
      display: '伪造请求',
      userId: 'user-42',
      walletAddress: created.address,
      nonce: 'nonce-mcp-00000002',
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    }, fake)
    const token = await createUnlockToken(PASSPHRASE, created.recovery_codes[0])
    const res = await client.callTool({
      name: 'signed_request_sign',
      arguments: { signed_request: req, unlock_token: token },
    })
    const out = JSON.parse((res.content[0] as { text: string }).text)
    expect(out.error).toBe('BAD_SIGNATURE')
  })

  it('用户拒绝确认 → USER_REJECTED', async () => {
    const client = await connect(() => false)
    const created = JSON.parse(((await client.callTool({ name: 'wallet_create', arguments: { passphrase: PASSPHRASE } })).content[0] as { text: string }).text)
    const req = issueSignedRequest({
      action: 'withdraw_confirm',
      intentHash: '0x' + '12'.repeat(32),
      display: '向 0x0000 提现 100 USDC',
      userId: 'user-42',
      walletAddress: created.address,
      nonce: 'nonce-mcp-00000003',
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    }, platformPriv)
    const token = await createUnlockToken(PASSPHRASE, created.recovery_codes[0])
    const res = await client.callTool({
      name: 'signed_request_sign',
      arguments: { signed_request: req, unlock_token: token },
    })
    const out = JSON.parse((res.content[0] as { text: string }).text)
    expect(out.error).toBe('USER_REJECTED')
  })
})
