import { describe, it, expect } from 'bun:test'
import { issueSignedRequest, verifySignedRequest, canonicalBytes } from '../src/signed-request'
import { generatePrivateKey, privateKeyToAddress } from '@wallet-service/core'

/** 平台密钥对 */
const platformPriv = generatePrivateKey()
const platformAddr = privateKeyToAddress(platformPriv)

/** 期望平台地址（另一把钥匙，用于验签失败场景） */
const otherPriv = generatePrivateKey()
const otherAddr = privateKeyToAddress(otherPriv)

function makeOptions(overrides: Partial<Parameters<typeof issueSignedRequest>[0]> = {}) {
  return {
    action: 'bind_wallet' as const,
    intentHash: '0x' + 'ab'.repeat(32),
    display: '绑定钱包到 envoytask 平台',
    userId: 'envoytask-user-42',
    walletAddress: '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf',
    nonce: 'nonce-1234567890abcdef',
    expiresAt: Math.floor(Date.now() / 1000) + 300,
    ...overrides,
  }
}

describe('signed_request v1', () => {
  it('平台签发 → 钱包验签通过（闭环）', () => {
    const req = issueSignedRequest(makeOptions(), platformPriv)
    const result = verifySignedRequest(req, platformAddr)
    expect(result.ok).toBe(true)
    expect(result.platformAddress?.toLowerCase()).toBe(platformAddr.toLowerCase())
  })

  it('过期请求 → EXPIRED', () => {
    const req = issueSignedRequest(makeOptions({ expiresAt: Math.floor(Date.now() / 1000) - 10 }), platformPriv)
    expect(verifySignedRequest(req, platformAddr).error).toBe('EXPIRED')
  })

  it('nonce 过短 → INVALID_FORMAT', () => {
    const req = issueSignedRequest(makeOptions({ nonce: 'short' }), platformPriv)
    expect(verifySignedRequest(req, platformAddr).error).toBe('INVALID_FORMAT')
  })

  it('签名被篡改 → BAD_SIGNATURE', () => {
    const req = issueSignedRequest(makeOptions(), platformPriv)
    const tampered = { ...req, display: '向攻击者地址提现 100 USDC' }
    expect(verifySignedRequest(tampered, platformAddr).error).toBe('BAD_SIGNATURE')
  })

  it('期望平台地址不匹配 → BAD_SIGNATURE（防伪造平台背书）', () => {
    const req = issueSignedRequest(makeOptions(), platformPriv)
    expect(verifySignedRequest(req, otherAddr).error).toBe('BAD_SIGNATURE')
  })

  it('非对象输入 → INVALID_FORMAT', () => {
    expect(verifySignedRequest(null, platformAddr).error).toBe('INVALID_FORMAT')
    expect(verifySignedRequest('junk', platformAddr).error).toBe('INVALID_FORMAT')
  })

  it('intent_hash 非 0x64hex → INVALID_FORMAT（字段格式校验）', () => {
    const req = issueSignedRequest(makeOptions(), platformPriv)
    const bad = { ...req, intent_hash: 'not-a-hash' }
    expect(verifySignedRequest(bad, platformAddr).error).toBe('INVALID_FORMAT')
  })

  it('wallet_address 非 0x40hex → INVALID_FORMAT', () => {
    const req = issueSignedRequest(makeOptions(), platformPriv)
    const bad = { ...req, wallet_address: 'junk' }
    expect(verifySignedRequest(bad, platformAddr).error).toBe('INVALID_FORMAT')
  })

  it('display 超长 → INVALID_FORMAT', () => {
    const req = issueSignedRequest(makeOptions(), platformPriv)
    const bad = { ...req, display: 'x'.repeat(201) }
    expect(verifySignedRequest(bad, platformAddr).error).toBe('INVALID_FORMAT')
  })

  it('expires_at 非整数 → EXPIRED/INVALID（防浮点时间）', () => {
    const req = issueSignedRequest(makeOptions(), platformPriv)
    const bad = { ...req, expires_at: 1234.56 }
    expect(verifySignedRequest(bad, platformAddr).error).toBeTruthy()
  })

  it('action 不在白名单 → INVALID_FORMAT', () => {
    const req = issueSignedRequest(makeOptions(), platformPriv)
    const bad = { ...req, action: 'steal_all_funds' }
    expect(verifySignedRequest(bad, platformAddr).error).toBe('INVALID_FORMAT')
  })

  it('user_id 空 → INVALID_FORMAT', () => {
    const req = issueSignedRequest(makeOptions(), platformPriv)
    const bad = { ...req, user_id: '' }
    expect(verifySignedRequest(bad, platformAddr).error).toBe('INVALID_FORMAT')
  })

  it('canonicalBytes 确定性 + length-prefixed 布局（O5）', () => {
    const a = makeOptions()
    const base = { v: 1 as const, action: a.action, intent_hash: a.intentHash, display: a.display, user_id: a.userId, wallet_address: a.walletAddress, nonce: a.nonce, expires_at: a.expiresAt }
    expect(canonicalBytes(base)).toEqual(canonicalBytes(base))
    // v(1) + action(len4+6) + intent(len4+32) + display(len4+n) + user_id(len4+n) + addr(len4+20) + nonce(len4+n) + expires(8)
    const bytes = canonicalBytes(base)
    const view = new DataView(bytes.buffer, bytes.byteOffset)
    expect(bytes[0]).toBe(1)
    const actionLen = view.getUint32(1, false)
    expect(actionLen).toBe(base.action.length)
    const intentLen = view.getUint32(1 + 4 + actionLen, false)
    expect(intentLen).toBe(32)
    // 尾部 8 字节 = expires_at（大端）
    const expOffset = bytes.length - 8
    expect(view.getBigUint64(expOffset, false)).toBe(BigInt(base.expires_at))
  })

  it('canonicalBytes 跨语言一致（Unicode UTF-8 字节直拼，不转义）', () => {
    const a = makeOptions()
    const base = { v: 1 as const, action: a.action, intent_hash: a.intentHash, display: '任务说明·中文', user_id: 'user-中-1', wallet_address: a.walletAddress, nonce: a.nonce, expires_at: a.expiresAt }
    const bytes = canonicalBytes(base)
    const view = new DataView(bytes.buffer, bytes.byteOffset)
    const actionLen = view.getUint32(1, false)
    const offDisplay = 1 + 4 + actionLen + 4 + 32
    const displayLen = view.getUint32(offDisplay, false)
    expect(displayLen).toBe(new TextEncoder().encode('任务说明·中文').length)
  })
})

describe('P1-5：验签对畸形输入返回结构化错误（不抛库异常）', () => {
  const valid = issueSignedRequest(makeOptions(), platformPriv)

  it('platform_signature undefined → BAD_SIGNATURE（不抛 TypeError）', () => {
    const bad = { ...valid, platform_signature: undefined }
    expect(() => verifySignedRequest(bad, platformAddr)).not.toThrow()
    expect(verifySignedRequest(bad, platformAddr).error).toBe('BAD_SIGNATURE')
  })

  it('platform_signature 非字符串（对象）→ BAD_SIGNATURE', () => {
    const bad = { ...valid, platform_signature: {} }
    expect(verifySignedRequest(bad, platformAddr).error).toBe('BAD_SIGNATURE')
  })

  it('platform_signature 非 hex / 长度非 130 → BAD_SIGNATURE', () => {
    const bad1 = { ...valid, platform_signature: 'zz'.repeat(65) }
    expect(verifySignedRequest(bad1, platformAddr).error).toBe('BAD_SIGNATURE')
    const bad2 = { ...valid, platform_signature: valid.platform_signature.slice(0, 128) } // 128 hex（旧矛盾长度）
    expect(verifySignedRequest(bad2, platformAddr).error).toBe('BAD_SIGNATURE')
  })

  it('130 hex 但全零签名（65 字节全 0）→ BAD_SIGNATURE（recoverSigner 异常被捕获）', () => {
    const bad = { ...valid, platform_signature: '00'.repeat(65) }
    expect(() => verifySignedRequest(bad, platformAddr)).not.toThrow()
    expect(verifySignedRequest(bad, platformAddr).error).toBe('BAD_SIGNATURE')
  })

  it('expectedPlatformAddress 格式非法 → INVALID_FORMAT（不抛）', () => {
    expect(verifySignedRequest(valid, 'not-an-address').error).toBe('INVALID_FORMAT')
  })
})
