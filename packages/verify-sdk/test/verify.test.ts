import { describe, it, expect } from 'bun:test'
import { secp256k1 } from '@noble/curves/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3'
import { recoverSigner, verifySignature } from '../src/index'

/** 用私钥签名（与 signer WalletVault 相同的 EIP-191 流程） */
function signWithPrivkey(priv: Uint8Array, message: string): Uint8Array {
  const msg = new TextEncoder().encode(message)
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${msg.length}`)
  const payload = new Uint8Array(prefix.length + msg.length)
  payload.set(prefix)
  payload.set(msg, prefix.length)
  const hash = keccak_256(payload)
  const sig = secp256k1.sign(hash, priv)
  const raw = sig.toCompactRawBytes()
  const out = new Uint8Array(65)
  out.set(raw)
  out[64] = sig.recovery ?? 0
  return out
}

const PRIV1 = new Uint8Array(32)
PRIV1[31] = 1 // → 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf

describe('verify-sdk', () => {
  it('验签还原出签名者地址（已知向量）', () => {
    const msg = 'bind wallet for test'
    const sig = signWithPrivkey(PRIV1, msg)
    expect(recoverSigner(msg, sig)).toBe('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')
  })

  it('verifySignature 地址匹配 → true', () => {
    const msg = 'withdraw confirm 50 USDC'
    const sig = signWithPrivkey(PRIV1, msg)
    expect(verifySignature(msg, sig, '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')).toBe(true)
  })

  it('地址不匹配 → false（防跨用户/跨地址）', () => {
    const msg = 'withdraw confirm 50 USDC'
    const sig = signWithPrivkey(PRIV1, msg)
    expect(verifySignature(msg, sig, '0x0000000000000000000000000000000000000000')).toBe(false)
  })

  it('消息被篡改 → 还原地址不同（防中间人）', () => {
    const sig = signWithPrivkey(PRIV1, 'original message')
    expect(verifySignature('tampered message', sig, '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')).toBe(false)
  })

  it('签名长度非法 → 抛错', () => {
    expect(() => recoverSigner('x', new Uint8Array(64))).toThrow(/65 bytes/)
  })
})
