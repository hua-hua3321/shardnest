import { describe, it, expect, beforeEach } from 'bun:test'
import { promises as fs } from 'node:fs'
import * as path from 'node:path'
import { getHomeDir } from '@wallet-services/cli'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { createShardnestServer, parsePlatformAddresses, loadPlatformAddresses } from '../src/index'
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

  it('serverInfo 版本与 package.json 一致（单一事实来源，防发布漂移）', async () => {
    const client = await connect()
    const pkg = JSON.parse(await fs.readFile(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }
    expect(client.getServerVersion()?.version).toBe(pkg.version)
    expect(client.getServerVersion()?.name).toBe('shardnest')
  })

  it('W12：默认 approval 下 wallet_wipe 拒绝（防 LLM 无确认删钱包）；CLI 短语不构成 MCP 防线', async () => {
    const client = await connectWithDefaultApproval()
    const created = await createWallet(client, PASSPHRASE)
    const res = await client.callTool({ name: 'wallet_wipe', arguments: { scope: 'all' } })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.error).toBe('USER_REJECTED')
    expect(res.isError).toBe(true)
    // 钱包未被删除（地址仍可读）
    const addrRes = await client.callTool({ name: 'wallet_address', arguments: {} })
    expect(((addrRes.content as unknown[])[0] as { text: string }).text).toBe(created.address)
  })

  it('wallet_wipe：用户拒绝确认 → USER_REJECTED（高风险闸门默认拒绝）', async () => {
    const client = await connect(() => false)
    const res = await client.callTool({ name: 'wallet_wipe', arguments: {} })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.error).toBe('USER_REJECTED')
    expect(res.isError).toBe(true)
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
    expect(res.isError).toBe(true)
  })

  it('wallet_mnemonic_export：用户拒绝确认 → USER_REJECTED（私钥提取闸门）', async () => {
    const client = await connect(() => false)
    const res = await client.callTool({ name: 'wallet_mnemonic_export', arguments: {} })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.error).toBe('USER_REJECTED')
    expect(res.isError).toBe(true)
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
    expect(res.isError).toBe(true)
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
    expect(res.isError).toBe(true)
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
    expect(res.isError).toBe(true)
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
    expect(res.isError).toBe(true)
  })

  it('P1-3：同 nonce 重放签名请求 → 第二次被拒（NONCE_REUSED，钱包侧兜底）', async () => {
    const client = await connect()
    const created = await createWallet(client, PASSPHRASE)
    const req = issueSignedRequest({
      action: 'bind_wallet',
      intentHash: '0x' + 'be'.repeat(32),
      display: '绑定钱包（重放测试）',
      userId: 'user-replay',
      walletAddress: created.address,
      nonce: 'nonce-mcp-replay-00000001',
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    }, platformPriv)
    // 首次签名：成功（消费第一个解锁令牌）
    const token1 = await createUnlockToken(PASSPHRASE, created.recoveryCodes[0])
    const r1 = await client.callTool({ name: 'signed_request_sign', arguments: { signed_request: req, unlock_token: token1 } })
    const out1 = JSON.parse(((r1.content as unknown[])[0] as { text: string }).text)
    expect(out1.address).toBe(created.address)
    // 同一 nonce 第二次出现（不同解锁令牌，模拟平台复用 nonce）→ 钱包侧拦截重放
    const token2 = await createUnlockToken(PASSPHRASE, created.recoveryCodes[0])
    const r2 = await client.callTool({ name: 'signed_request_sign', arguments: { signed_request: req, unlock_token: token2 } })
    const out2 = JSON.parse(((r2.content as unknown[])[0] as { text: string }).text)
    expect(out2.error).toBe('NONCE_REUSED')
    expect(r2.isError).toBe(true)
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
    expect(res.isError).toBe(true)
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
    expect(res.isError).toBe(true)
  })

  it('多平台：白名单数组内另一平台签发 → 签名成功（验签绑定实际签发方）', async () => {
    const platformBPriv = generatePrivateKey()
    const platformBAddr = privateKeyToAddress(platformBPriv)
    // 服务器配置为「平台 A + 平台 B」白名单
    const server = createShardnestServer(() => true, [platformAddr, platformBAddr])
    const client = new Client({ name: 'test-client', version: '1.0.0' })
    const [c2s, s2c] = InMemoryTransport.createLinkedPair()
    await Promise.all([server.connect(s2c), client.connect(c2s)])

    const created = await createWallet(client, PASSPHRASE)
    // 平台 B 签发（非默认平台 A）
    const req = issueSignedRequest({
      action: 'sign_message',
      intentHash: '0x' + 'ff'.repeat(32),
      display: '平台 B 的消息签名请求',
      userId: 'user-b',
      walletAddress: created.address,
      nonce: 'nonce-mcp-00000004',
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    }, platformBPriv)
    const token = await createUnlockToken(PASSPHRASE, created.recoveryCodes[0])
    const res = await client.callTool({
      name: 'signed_request_sign',
      arguments: { signed_request: req, unlock_token: token },
    })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.address).toBe(created.address)
    // 签名必须绑定平台 B 地址（验签还原地址用平台 B 才能成功）
    const sig = Uint8Array.from(Buffer.from(out.signature, 'hex'))
    const withB = recoverSigner(walletSignMessage({ ...req, platform_address: platformBAddr }), sig)
    expect(withB.toLowerCase()).toBe(created.address.toLowerCase())
    const withA = recoverSigner(walletSignMessage({ ...req, platform_address: platformAddr }), sig)
    expect(withA.toLowerCase()).not.toBe(created.address.toLowerCase())
  })

  it('多平台：白名单外的平台 → BAD_SIGNATURE 拒绝', async () => {
    const outsiderPriv = generatePrivateKey()
    const outsiderAddr = privateKeyToAddress(outsiderPriv)
    const server = createShardnestServer(() => true, [platformAddr, outsiderAddr])
    const client = new Client({ name: 'test-client', version: '1.0.0' })
    const [c2s, s2c] = InMemoryTransport.createLinkedPair()
    await Promise.all([server.connect(s2c), client.connect(c2s)])

    const created = await createWallet(client, PASSPHRASE)
    const strangerPriv = generatePrivateKey() // 第三个平台（不在白名单）
    const req = issueSignedRequest({
      action: 'sign_message',
      intentHash: '0x' + 'aa'.repeat(32),
      display: '陌生平台请求',
      userId: 'user-x',
      walletAddress: created.address,
      nonce: 'nonce-mcp-00000005',
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    }, strangerPriv)
    const token = await createUnlockToken(PASSPHRASE, created.recoveryCodes[0])
    const res = await client.callTool({
      name: 'signed_request_sign',
      arguments: { signed_request: req, unlock_token: token },
    })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.error).toBe('BAD_SIGNATURE')
    expect(res.isError).toBe(true)
  })

  it('评审 F4：默认 approval 下 wallet_restore 拒绝（破坏性操作须用户确认）', async () => {
    const client = await connectWithDefaultApproval()
    const created = await createWallet(client, PASSPHRASE)
    const res = await client.callTool({
      name: 'wallet_restore',
      arguments: {
        passphrase_token: await createPassphraseSession(PASSPHRASE, 'restore'),
        expected_address: created.address,
      },
    })
    const out = JSON.parse(((res.content as unknown[])[0] as { text: string }).text)
    expect(out.error).toBe('USER_REJECTED')
    expect(res.isError).toBe(true)
  })

  it('评审 F7：无效解锁令牌不消耗 nonce（重放记录在令牌消费后）', async () => {
    const client = await connect()
    const created = await createWallet(client, PASSPHRASE)
    const req = issueSignedRequest({
      action: 'sign_message',
      intentHash: '0x' + '77'.repeat(32),
      display: 'F7 nonce 不被无效令牌烧掉',
      userId: 'user-f7',
      walletAddress: created.address,
      nonce: 'nonce-mcp-f7-00000001',
      expiresAt: Math.floor(Date.now() / 1000) + 300,
    }, platformPriv)
    // 第一次：无效令牌 → UNLOCK_INVALID（不应记录 nonce）
    const r1 = await client.callTool({
      name: 'signed_request_sign',
      arguments: { signed_request: req, unlock_token: '0'.repeat(64) },
    })
    expect(JSON.parse(((r1.content as unknown[])[0] as { text: string }).text).error).toBe('UNLOCK_INVALID')
    // 第二次：有效令牌 → 签名成功（证明 nonce 未被无效令牌烧掉）
    const token = await createUnlockToken(PASSPHRASE, created.recoveryCodes[0])
    const r2 = await client.callTool({
      name: 'signed_request_sign',
      arguments: { signed_request: req, unlock_token: token },
    })
    const out2 = JSON.parse(((r2.content as unknown[])[0] as { text: string }).text)
    expect(out2.address).toBe(created.address)
  })
})

describe('多平台配置解析（双通道）', () => {
  it('parsePlatformAddresses：逗号分隔 + 空白容忍 + 空值回退', () => {
    expect(parsePlatformAddresses('0x1111111111111111111111111111111111111111, 0x2222222222222222222222222222222222222222 '))
      .toEqual(['0x1111111111111111111111111111111111111111', '0x2222222222222222222222222222222222222222'])
    expect(parsePlatformAddresses('0x1111111111111111111111111111111111111111')).toHaveLength(1)
    expect(parsePlatformAddresses(undefined)).toEqual([])
    expect(parsePlatformAddresses('  ,  ')).toEqual([])
    expect(parsePlatformAddresses('')).toEqual([])
  })

  it('loadPlatformAddresses：仅 env 通道（单平台/逗号分隔）', async () => {
    const prev = process.env.SHARDNEST_PLATFORM_ADDRESS
    const prevCfg = process.env.SHARDNEST_PLATFORM_CONFIG
    delete process.env.SHARDNEST_PLATFORM_CONFIG
    process.env.SHARDNEST_PLATFORM_ADDRESS = '0x1111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222'
    try {
      expect(await loadPlatformAddresses()).toHaveLength(2)
    } finally {
      if (prev === undefined) delete process.env.SHARDNEST_PLATFORM_ADDRESS
      else process.env.SHARDNEST_PLATFORM_ADDRESS = prev
      if (prevCfg === undefined) delete process.env.SHARDNEST_PLATFORM_CONFIG
      else process.env.SHARDNEST_PLATFORM_CONFIG = prevCfg
    }
  })

  it('loadPlatformAddresses：env + 配置文件合并；格式非法 → 抛错拒绝启动', async () => {
    const prevCfg = process.env.SHARDNEST_PLATFORM_CONFIG
    const cfgPath = path.join(TEST_HOME, 'platforms.json')
    await fs.mkdir(TEST_HOME, { recursive: true })
    await fs.writeFile(cfgPath, JSON.stringify([{ name: 'exchange-a', address: '0x3333333333333333333333333333333333333333' }]))
    process.env.SHARDNEST_PLATFORM_CONFIG = cfgPath
    try {
      const addrs = await loadPlatformAddresses()
      expect(addrs).toContain('0x3333333333333333333333333333333333333333')
      // 非法 JSON → 拒绝启动
      await fs.writeFile(cfgPath, '{not json')
      await expect(loadPlatformAddresses()).rejects.toThrow(/JSON/)
      // 非数组 → 拒绝启动
      await fs.writeFile(cfgPath, JSON.stringify({ name: 'x', address: '0x3333333333333333333333333333333333333333' }))
      await expect(loadPlatformAddresses()).rejects.toThrow(/数组/)
      // 评审 F6：地址格式非法 → 拒绝启动（不静默全拒）
      await fs.writeFile(cfgPath, JSON.stringify([{ name: 'x', address: 'junk' }]))
      await expect(loadPlatformAddresses()).rejects.toThrow(/格式非法/)
      await fs.writeFile(cfgPath, JSON.stringify([{ name: 'x', address: '  ' }]))
      await expect(loadPlatformAddresses()).rejects.toThrow(/格式非法/)
    } finally {
      if (prevCfg === undefined) delete process.env.SHARDNEST_PLATFORM_CONFIG
      else process.env.SHARDNEST_PLATFORM_CONFIG = prevCfg
    }
  })
})
