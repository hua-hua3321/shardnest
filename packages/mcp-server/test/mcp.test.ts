import { describe, it, expect, beforeEach } from 'bun:test'
import { promises as fs } from 'node:fs'
import * as path from 'node:path'
import { getHomeDir } from '@wallet-services/cli'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { createShardnestServer } from '../src/index'
import { issueSignedRequest, walletSignMessage } from '@wallet-services/protocol'
import { generatePrivateKey, privateKeyToAddress } from '@wallet-services/core'
import { recoverSigner } from '@wallet-services/verify-sdk'
import { createUnlockToken } from '@wallet-services/cli'
import {createPassphraseSession, defaultApproval} from '@wallet-services/signer'

const TEST_HOME = path.join(process.cwd(), '.test-shardnest-mcp')

// P0-1：模块加载阶段固定 SHARDNEST_HOME（beforeEach 内删 TEST_HOME 常量前，
// 确保 getHomeDir()/getUnlockDir() 不会落到真实 ~/.shardnest）
process.env.SHARDNEST_HOME = TEST_HOME

/** P0-1 路径守卫：只允许删除明确的测试目录 */
async function rmTestHome(): Promise<void> {
  if (!TEST_HOME.includes('.test-shardnest-')) {
    throw new Error(`拒绝删除非测试目录: ${TEST_HOME}`)
  }
  await fs.rm(TEST_HOME, { recursive: true, force: true })
}

beforeEach(async () => {
  await rmTestHome()
})

const platformPriv = generatePrivateKey()
const platformAddr = privateKeyToAddress(platformPriv)
const PASSPHRASE = 'mcp-passphrase-123!'

/** 创建钱包并返回（地址 + 从本地文件读取的恢复码）；口令经口令令牌传递（不进 LLM） */
async function createWallet(client: Client, passphrase: string, email?: string) {
  const token = await createPassphraseSession(passphrase)
  const res = await client.callTool({ name: 'wallet_create', arguments: { passphrase_token: token, email } })
  const data = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
  const fileContent = await fs.readFile(path.join(getHomeDir(), 'recovery-codes.txt'), 'utf8')
  const recoveryCodes = fileContent.split('\n').filter((l) => /^(sn1|sn2)-/.test(l.trim()))
  return { address: data.address, recoveryCodes, data }
}

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

/** 生产默认配置连接（defaultApproval：仅 sign_message 放行，高风险全拒） */
async function connectWithDefaultApproval() {
  const server = createShardnestServer(defaultApproval, platformAddr)
  const client = new Client({ name: 'test-client', version: '1.0.0' })
  const [c2s, s2c] = InMemoryTransport.createLinkedPair()
  await Promise.all([server.connect(s2c), client.connect(c2s)])
  return client
}

describe('shardnest MCP 薄壳', () => {
  it('注册 6 个工具', async () => {
    const client = await connect()
    const tools = await client.listTools()
    const names = tools.tools.map((t) => t.name).sort()
    expect(names).toEqual([
      'signed_request_sign',
      'wallet_address',
      'wallet_create',
      'wallet_mnemonic_export',
      'wallet_restore',
      'wallet_wipe',
    ])
  })

  it('W12：默认 approval 下 wallet_wipe 拒绝（防 LLM 无确认删钱包）；CLI 短语不构成 MCP 防线', async () => {
    const client = await connectWithDefaultApproval()
    const created = await createWallet(client, PASSPHRASE)
    const res = await client.callTool({ name: 'wallet_wipe', arguments: { scope: 'all' } })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.error).toBe('USER_REJECTED')
    // 钱包未被删除（地址仍可读）
    const addrRes = await client.callTool({ name: 'wallet_address', arguments: {} })
    expect(((addrRes.content as unknown[])[0] as { text: string }).text).toBe(created.address)
  })

  it('wallet_wipe：用户拒绝确认 → USER_REJECTED（高风险闸门默认拒绝）', async () => {
    const client = await connect(() => false)
    const res = await client.callTool({ name: 'wallet_wipe', arguments: {} })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.error).toBe('USER_REJECTED')
  })

  it('wallet_wipe：宿主放行 + 默认 scope=saved → 仅删明文备份，钱包保留', async () => {
    const client = await connect(() => true) // 宿主注入放行 approval（如 OS 弹窗确认）
    const created = await createWallet(client, PASSPHRASE)
    const res = await client.callTool({ name: 'wallet_wipe', arguments: {} })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.removed).toContain('recovery-codes.txt')
    expect(out.removed).not.toContain('device-share.json')
    expect(out.warning).toContain('钱包本体保留')
    // 钱包地址仍可读
    const addrRes = await client.callTool({ name: 'wallet_address', arguments: {} })
    expect(((addrRes.content as unknown[])[0] as { text: string }).text).toBe(created.address)
  })

  it('wallet_wipe：宿主放行 + scope=all → 本机密钥材料彻底删除', async () => {
    const client = await connect(() => true) // 宿主注入放行 approval（如 OS 弹窗确认）
    const created = await createWallet(client, PASSPHRASE)
    expect(created.recoveryCodes.length).toBeGreaterThan(0)
    const res = await client.callTool({ name: 'wallet_wipe', arguments: { scope: 'all' } })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.removed_count).toBeGreaterThanOrEqual(3)
    expect(out.warning).toContain('不可恢复')
    // 本地恢复码文件已删除
    await expect(fs.readFile(path.join(getHomeDir(), 'recovery-codes.txt'))).rejects.toThrow()
  })

  it('wallet_create → 返回地址 + 恢复码', async () => {
    const client = await connect()
    const created = await createWallet(client, PASSPHRASE)
    expect(created.address).toMatch(/^0x[0-9a-fA-F]{40}$/)
    expect(created.recoveryCodes.length).toBe(2)
  })

  it('wallet_create generate_mnemonic=true → 返回助记词文件路径（不经 LLM）', async () => {
    const client = await connect()
    const token = await createPassphraseSession(PASSPHRASE)
    const res = await client.callTool({
      name: 'wallet_create',
      arguments: { passphrase_token: token, generate_mnemonic: true },
    })
    const data = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    // 凭证隔离：助记词内容不进 LLM，只给文件路径
    expect(data.mnemonic_file).toBeTruthy()
    expect(data.mnemonic).toBeUndefined()
    // 文件为 24 词
    const fileContent = await fs.readFile(data.mnemonic_file, 'utf8')
    const mnemonic = fileContent.split('\n').find((l) => l.trim().split(/\s+/).length === 24)!.trim()
    expect(mnemonic.split(' ').length).toBe(24)
  })

  it('wallet_mnemonic_export：本地恢复码文件导出助记词 → 只返回文件路径（不经 LLM）', async () => {
    const client = await connect()
    await createWallet(client, PASSPHRASE) // 默认不生成助记词
    const res = await client.callTool({ name: 'wallet_mnemonic_export', arguments: {} })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.mnemonic_file).toBeTruthy()
    expect(out.mnemonic).toBeUndefined()
    const fileContent = await fs.readFile(out.mnemonic_file, 'utf8')
    const mnemonic = fileContent.split('\n').find((l) => l.trim().split(/\s+/).length === 24)!.trim()
    expect(mnemonic.split(' ').length).toBe(24)
    expect(out.warning).toContain('单点')
  })

  it('wallet_create 默认不生成助记词', async () => {
    const client = await connect()
    const token = await createPassphraseSession(PASSPHRASE)
    const res = await client.callTool({ name: 'wallet_create', arguments: { passphrase_token: token } })
    const data = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(data.mnemonic_file).toBeNull()
  })

  it('wallet_create 带 email → 返回 backup 状态 + 恢复码文件路径（不经 LLM）', async () => {
    const client = await connect()
    const created = await createWallet(client, PASSPHRASE, 'user@example.com')
    expect(created.data.backup_email).toBe('user@example.com')
    expect(created.data.backup_status).toBe('skipped')
    // 恢复码不经 LLM：响应只含文件路径
    expect(created.data.recovery_codes_file).toBeTruthy()
    expect(created.data.recovery_codes).toBeUndefined()
    expect(created.recoveryCodes.length).toBe(2)
  })

  it('wallet_restore：文件路径穿越 → 拒绝（任意文件读取防护）', async () => {
    const client = await connect()
    const created = await createWallet(client, PASSPHRASE)
    const res = await client.callTool({
      name: 'wallet_restore',
      arguments: {
        passphrase_token: await createPassphraseSession(PASSPHRASE, 'restore'),
        expected_address: created.address,
        mnemonic_file_path: '/etc/passwd', // 钱包目录外路径
      },
    })
    // assertSafePath 抛错 → 结构化 RESTORE_FAILED（isError=false），message 含路径约束说明
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.error).toBe('RESTORE_FAILED')
    expect(out.message).toMatch(/钱包目录|逃逸/)
  })

  it('wallet_mnemonic_export：用户拒绝确认 → USER_REJECTED（私钥提取闸门）', async () => {
    const client = await connect(() => false)
    const res = await client.callTool({ name: 'wallet_mnemonic_export', arguments: {} })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.error).toBe('USER_REJECTED')
  })

  it('wallet_restore：恢复码经本地文件读取 → 新恢复码只返回文件路径（凭证隔离）', async () => {
    const client = await connect()
    // 1. 创建钱包（恢复码落盘 recovery-codes.txt）
    const created = await createWallet(client, PASSPHRASE)
    // 2. 恢复：期望地址校验 + 恢复码从文件读取（不经 LLM）
    const res = await client.callTool({
      name: 'wallet_restore',
      arguments: {
        passphrase_token: await createPassphraseSession(PASSPHRASE, 'restore'),
        expected_address: created.address,
      },
    })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.address).toBe(created.address)
    // 凭证隔离：响应无恢复码明文，只有文件路径
    expect(out.recovery_codes).toBeUndefined()
    expect(out.recovery_codes_file).toBeTruthy()
    expect(out.note).toBeTruthy()
    // 3. 新恢复码文件可读取（2 片）
    const fileCodes = (await fs.readFile(path.join(getHomeDir(), 'recovery-codes.txt'), 'utf8'))
      .split('\n').filter((l) => /^(sn1|sn2)-/.test(l.trim()))
    expect(fileCodes.length).toBe(2)
  })

  it('P1-7：口令令牌绑定操作——create 令牌用于 wallet_restore → 拒绝', async () => {
    const client = await connect()
    const created = await createWallet(client, PASSPHRASE)
    // create 令牌（默认 purpose=create）用于 restore → 用途不匹配
    const res = await client.callTool({
      name: 'wallet_restore',
      arguments: {
        passphrase_token: await createPassphraseSession(PASSPHRASE, 'create'),
        expected_address: created.address,
      },
    })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.error).toBe('RESTORE_FAILED')
    expect(out.message).toMatch(/用途不匹配/)
    // restore 令牌用于 restore → 成功
    const okRes = await client.callTool({
      name: 'wallet_restore',
      arguments: {
        passphrase_token: await createPassphraseSession(PASSPHRASE, 'restore'),
        expected_address: created.address,
      },
    })
    const ok = JSON.parse(((okRes.content as unknown[])[0] as { text: string }).text)
    expect(ok.address).toBe(created.address)
  })

  it('wallet_restore 期望地址不匹配 → RESTORE_FAILED（防输错恢复码）', async () => {
    const client = await connect()
    const created = await createWallet(client, PASSPHRASE)
    const res = await client.callTool({
      name: 'wallet_restore',
      arguments: {
        passphrase_token: await createPassphraseSession(PASSPHRASE, 'restore'),
        expected_address: '0x0000000000000000000000000000000000000000',
      },
    })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.error).toBe('RESTORE_FAILED')
  })

  it('wallet_create 无效口令令牌 → 错误（口令令牌单次/过期防护）', async () => {
    const client = await connect()
    const res = await client.callTool({ name: 'wallet_create', arguments: { passphrase_token: '0'.repeat(64) } })
    // MCP SDK 将 handler 异常转为 isError + 错误文本
    expect(res.isError).toBe(true)
    const text = (res.content as unknown[])[0] as { type: string; text: string }
    expect(text.text.includes('不存在') || text.text.includes('已被使用')).toBe(true)
  })

  it('signed_request_sign：平台背书 → 确认 → 返回可验签签名', async () => {
    const client = await connect()
    // 1. 创建钱包（地址 + 本地恢复码文件，不经 LLM）
    const created = await createWallet(client, PASSPHRASE)
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
    const token = await createUnlockToken(PASSPHRASE, created.recoveryCodes[0])
    // 4. 签名（验背书 → 地址校验 → 确认 → 令牌消费 → 本地签名）
    const signRes = await client.callTool({
      name: 'signed_request_sign',
      arguments: { signed_request: req, unlock_token: token },
    })
    const out = JSON.parse(((signRes.content as unknown[])[0] as { text: string }).text)
    expect(out.address).toBe(created.address)
    // 5. 验签还原同一地址（平台侧可验证；P1-6: 用 walletSignMessage 重建签名消息）
    const sig = Uint8Array.from(Buffer.from(out.signature, 'hex'))
    const recovered = recoverSigner(walletSignMessage({ ...req, platform_address: platformAddr }), sig)
    expect(recovered.toLowerCase()).toBe(created.address.toLowerCase())
    // P1-6: 签名绑定 nonce——改用不同 nonce 验签必然还原不同地址（防跨请求复用）
    const otherNonce = recoverSigner(walletSignMessage({ ...req, nonce: 'other-nonce-1234567890', platform_address: platformAddr }), sig)
    expect(otherNonce.toLowerCase()).not.toBe(created.address.toLowerCase())
    // P1-6: 签名绑定平台身份——不同平台地址验签还原不同签名者（防跨平台复用）
    const otherPlatform = recoverSigner(walletSignMessage({ ...req, platform_address: '0x1111111111111111111111111111111111111111' }), sig)
    expect(otherPlatform.toLowerCase()).not.toBe(created.address.toLowerCase())
    // P1-6: 签名绑定 user_id——不同用户验签还原不同签名者（防跨用户复用）
    const otherUser = recoverSigner(walletSignMessage({ ...req, user_id: 'user-99', platform_address: platformAddr }), sig)
    expect(otherUser.toLowerCase()).not.toBe(created.address.toLowerCase())
  })

  it('wallet_address 与本地不一致 → WALLET_ADDRESS_MISMATCH 拒绝（纵深防御）', async () => {
    const client = await connect()
    const created = await createWallet(client, PASSPHRASE)
    const token = await createUnlockToken(PASSPHRASE, created.recoveryCodes[0])
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
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.error).toBe('WALLET_ADDRESS_MISMATCH')
  })

  it('无效解锁令牌 → UNLOCK_INVALID（单次使用 + 过期防护）', async () => {
    const client = await connect()
    const created = await createWallet(client, PASSPHRASE)
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
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.error).toBe('UNLOCK_INVALID')
  })

  it('伪造背书（非平台签发）→ BAD_SIGNATURE 拒绝', async () => {
    const client = await connect()
    const fake = generatePrivateKey()
    const created = await createWallet(client, PASSPHRASE)
    const req = issueSignedRequest({
      action: 'bind_wallet',
      intentHash: '0x' + 'ef'.repeat(32),
      display: '伪造请求',
      userId: 'user-42',
      walletAddress: created.address,
      nonce: 'nonce-mcp-00000002',
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    }, fake)
    const token = await createUnlockToken(PASSPHRASE, created.recoveryCodes[0])
    const res = await client.callTool({
      name: 'signed_request_sign',
      arguments: { signed_request: req, unlock_token: token },
    })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.error).toBe('BAD_SIGNATURE')
  })

  it('用户拒绝确认 → USER_REJECTED', async () => {
    const client = await connect(() => false)
    const created = await createWallet(client, PASSPHRASE)
    const req = issueSignedRequest({
      action: 'withdraw_confirm',
      intentHash: '0x' + '12'.repeat(32),
      display: '向 0x0000 提现 100 USDC',
      userId: 'user-42',
      walletAddress: created.address,
      nonce: 'nonce-mcp-00000003',
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    }, platformPriv)
    const token = await createUnlockToken(PASSPHRASE, created.recoveryCodes[0])
    const res = await client.callTool({
      name: 'signed_request_sign',
      arguments: { signed_request: req, unlock_token: token },
    })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.error).toBe('USER_REJECTED')
  })
})
