import { describe, it, expect, beforeEach } from 'bun:test'
import { promises as fs } from 'node:fs'
import * as path from 'node:path'
import {
  createUnlockSession,
  consumeUnlockSession,
  createPassphraseSession,
  consumePassphraseSession,
  getUnlockDir,
} from '../src/unlock-session'

const TEST_HOME = path.join(process.cwd(), '.test-shardnest-session')

// 模块加载阶段固定 SHARDNEST_HOME（测试隔离，防触碰真实钱包）
process.env.SHARDNEST_HOME = TEST_HOME

beforeEach(async () => {
  if (!TEST_HOME.includes('.test-shardnest-')) {
    throw new Error(`拒绝删除非测试目录: ${TEST_HOME}`)
  }
  await fs.rm(TEST_HOME, { recursive: true, force: true })
})

/** 定位并篡改会话文件密文外的 purpose 字段（模拟本机文件被修改） */
async function tamperPurpose(token: string, newPurpose: string | null): Promise<void> {
  const file = path.join(getUnlockDir(), `passphrase-${token.slice(0, 16)}.bin`)
  const data = JSON.parse(await fs.readFile(file, 'utf8')) as { purpose?: string | null }
  data.purpose = newPurpose
  await fs.writeFile(file, JSON.stringify(data))
}

describe('口令会话 purpose 绑定（P1-7 + GCM AAD 认证）', () => {
  it('create 令牌按 create 用途正常消费', async () => {
    const token = await createPassphraseSession('test-passphrase-123!', 'create')
    expect(await consumePassphraseSession(token, 'create')).toBe('test-passphrase-123!')
  })

  it('create 令牌用于 restore → 拒绝（用途不匹配）', async () => {
    const token = await createPassphraseSession('test-passphrase-123!', 'create')
    await expect(consumePassphraseSession(token, 'restore')).rejects.toThrow(/用途不匹配/)
  })

  it('v:3 密文外 purpose 被篡改为 null → 拒绝（不再经 null 分支放行）', async () => {
    const token = await createPassphraseSession('test-passphrase-123!', 'create')
    await tamperPurpose(token, null)
    await expect(consumePassphraseSession(token, 'create')).rejects.toThrow()
  })

  it('v:3 密文外 purpose 被篡改为其他合法值 → 拒绝（GCM AAD 认证失败）', async () => {
    const token = await createPassphraseSession('test-passphrase-123!', 'create')
    await tamperPurpose(token, 'restore')
    await expect(consumePassphraseSession(token, 'create')).rejects.toThrow()
  })

  it('unlock 类型（无 purpose）v:3 正常消费，私钥还原一致', async () => {
    const priv = new Uint8Array(32)
    priv[31] = 1
    const token = await createUnlockSession(priv)
    const out = await consumeUnlockSession(token)
    expect(Buffer.from(out).toString('hex')).toBe(Buffer.from(priv).toString('hex'))
  })

  it('P1-7 加固：误建的 null-purpose 口令会话（底层 createUnlockSession 不带 purpose）→ 拒绝', async () => {
    // 直接走底层 API 创建不带 purpose 的 passphrase 会话，模拟误用/历史会话。
    // unlock 会话单次使用，每条断言使用独立 token。
    const bytes = new TextEncoder().encode('test-passphrase-123!')
    const tokenCreate = await createUnlockSession(bytes, 'passphrase')
    await expect(consumePassphraseSession(tokenCreate, 'create')).rejects.toThrow(/用途不匹配|缺失/)
    const tokenRestore = await createUnlockSession(bytes, 'passphrase')
    await expect(consumePassphraseSession(tokenRestore, 'restore')).rejects.toThrow(/用途不匹配|缺失/)
  })

  it('P1-7 加固：passphrase 会话消费漏传 purpose → 拒绝（防调用方静默绕过绑定）', async () => {
    const token = await createPassphraseSession('test-passphrase-123!', 'create')
    // consumeUnlockSession 的 purpose 形参缺省 undefined；passphrase 类型下必须被拒
    await expect(consumeUnlockSession(token, 'passphrase')).rejects.toThrow(/用途不匹配|缺失/)
  })
})
