import { describe, it, expect, beforeEach } from 'bun:test'
import { promises as fs } from 'node:fs'
import * as path from 'node:path'
import {
  getHomeDir,
  initWallet,
  getAddress,
  signMessage,
  restoreWallet,
  encodeRecoveryCode,
  decodeRecoveryCode,
} from '../src/commands'
import { secp256k1 } from '@noble/curves/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3'

const TEST_HOME = path.join(process.cwd(), '.test-shardnest-home')

beforeEach(async () => {
  await fs.rm(getHomeDir(), { recursive: true, force: true })
  process.env.SHARDNEST_HOME = TEST_HOME
})

const PASSPHRASE = 'test-passphrase-123!'

describe('CLI 钱包流程（init → sign → restore 全闭环）', () => {
  it('init 创建钱包：地址存在、恢复码 2 个、设备片文件加密存储', async () => {
    const result = await initWallet(PASSPHRASE)
    expect(result.address).toMatch(/^0x[0-9a-fA-F]{40}$/)
    expect(result.recoveryCodes.length).toBe(2)
    // 设备片文件存在且不含明文私钥材料
    const raw = await fs.readFile(path.join(getHomeDir(), 'device-share.json'), 'utf8')
    expect(raw).not.toContain('privateKey')
    // 地址无需口令可读
    expect(await getAddress()).toBe(result.address)
  })

  it('init → sign：EIP-191 签名验签还原同一地址', async () => {
    const result = await initWallet(PASSPHRASE)
    const out = JSON.parse(await signMessage(PASSPHRASE, result.recoveryCodes[0], 'hello shardnest'))
    expect(out.address).toBe(result.address)
    // 验签
    const sig = Uint8Array.from(Buffer.from(out.signature, 'hex'))
    const msg = new TextEncoder().encode('hello shardnest')
    const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${msg.length}`)
    const payload = new Uint8Array(prefix.length + msg.length)
    payload.set(prefix)
    payload.set(msg, prefix.length)
    const hash = keccak_256(payload)
    const pub = secp256k1.Signature.fromCompact(sig.slice(0, 64))
      .addRecoveryBit(sig[64])
      .recoverPublicKey(hash)
      .toRawBytes(false)
    const addrHash = keccak_256(pub.slice(1))
    const recovered = `0x${Array.from(addrHash.slice(12)).map((b) => b.toString(16).padStart(2, '0')).join('')}`
    expect(recovered.toLowerCase()).toBe(result.address.toLowerCase())
  })

  it('错误口令解密失败（AES-GCM 认证失败）', async () => {
    await initWallet(PASSPHRASE)
    await expect(signMessage('wrong-passphrase', 'sn1-2-00', 'x')).rejects.toThrow()
  })

  it('restore：用 2 个恢复码恢复出同一地址，且新恢复码可签名', async () => {
    const first = await initWallet(PASSPHRASE)
    // 模拟设备丢失：删除设备文件
    await fs.rm(getHomeDir(), { recursive: true, force: true })
    // 用旧恢复码恢复（新口令）
    const restored = await restoreWallet('new-passphrase-456!', [first.recoveryCodes[0], first.recoveryCodes[1]])
    expect(restored.address).toBe(first.address)
    // 新恢复码可签名
    const out = JSON.parse(await signMessage('new-passphrase-456!', restored.recoveryCodes[0], 'after restore'))
    expect(out.address).toBe(first.address)
  })

  it('init 提供邮箱：未配置 SMTP → backupStatus=skipped（备份回退手动）', async () => {
    const result = await initWallet(PASSPHRASE, 'user@example.com')
    expect(result.backupEmail).toBe('user@example.com')
    expect(result.backupStatus).toBe('skipped')
  })

  it('init 邮箱格式无效 → 抛错（不发信不建号）', async () => {
    await expect(initWallet(PASSPHRASE, 'not-an-email')).rejects.toThrow(/邮箱格式无效/)
  })

  it('恢复码编解码往返一致（含 CRC 校验）', () => {
    const share = { index: 7, bytes: new Uint8Array([1, 2, 3, 255]) }
    expect(decodeRecoveryCode(encodeRecoveryCode(share))).toEqual(share)
    expect(() => decodeRecoveryCode('bad-format')).toThrow()
  })

  it('恢复码 CRC 被篡改 → 解码抛错（防手输/OCR 错误静默恢复错误钱包）', () => {
    const share = { index: 7, bytes: new Uint8Array([1, 2, 3, 255]) }
    const code = encodeRecoveryCode(share)
    const tampered = code.slice(0, -1) + (code.endsWith('0') ? '1' : '0')
    expect(() => decodeRecoveryCode(tampered)).toThrow(/校验失败/)
  })

  it('restore 地址不匹配（expectedAddress 错误）→ 抛错中止', async () => {
    const first = await initWallet(PASSPHRASE)
    await expect(
      restoreWallet(PASSPHRASE, [first.recoveryCodes[0], first.recoveryCodes[1]], '0x0000000000000000000000000000000000000000'),
    ).rejects.toThrow(/不一致/)
  })

  it('口令 <12 位 → 拒绝（强度校验）', async () => {
    await expect(initWallet('short')).rejects.toThrow(/至少 12 位/)
  })
})
