import { describe, it, expect } from 'bun:test'
import { entropyToMnemonic, mnemonicToEntropy, derivePrivateKeyFromMnemonic, derivePrivateKeyFromEntropy, isLikelyMnemonic } from '../src/mnemonic'
import { bytesToHex } from '@noble/hashes/utils'

describe('BIP-39 助记词（O4A: 熵为根，标准语义）', () => {
  it('BIP-39 官方测试向量：全零熵 → 24 词（标准词表）', () => {
    const entropy = new Uint8Array(32) // 全零
    const mnemonic = entropyToMnemonic(entropy)
    // BIP-39 向量：0000...0（256 位）→ "abandon abandon ... about"
    expect(mnemonic.split(' ').length).toBe(24)
    expect(mnemonic.split(' ')[0]).toBe('abandon')
    expect(mnemonic.split(' ')[23]).toBe('art') // BIP-39 官方向量第 24 词
  })

  it('熵↔助记词往返一致（可逆编码）', () => {
    const entropy = new Uint8Array(32)
    entropy[0] = 0xab; entropy[15] = 0xcd; entropy[31] = 0xef
    const mnemonic = entropyToMnemonic(entropy)
    expect(mnemonicToEntropy(mnemonic)).toEqual(entropy)
  })

  it('非 32 字节输入 → 拒绝', () => {
    expect(() => entropyToMnemonic(new Uint8Array(16))).toThrow() // 12 词容量不足
  })

  it('校验和篡改 → 拒绝（抄错即失败）', () => {
    const entropy = new Uint8Array(32).fill(7)
    const mnemonic = entropyToMnemonic(entropy)
    const words = mnemonic.split(' ')
    words[23] = words[23] === 'about' ? 'abandon' : 'about'
    expect(() => mnemonicToEntropy(words.join(' '))).toThrow()
  })

  it('派生确定性：同一助记词 → 同一私钥；不同熵 → 不同私钥', () => {
    const e1 = new Uint8Array(32).fill(1)
    const e2 = new Uint8Array(32).fill(2)
    const k1a = derivePrivateKeyFromEntropy(e1)
    const k1b = derivePrivateKeyFromEntropy(e1)
    const k2 = derivePrivateKeyFromEntropy(e2)
    expect(bytesToHex(k1a)).toBe(bytesToHex(k1b))
    expect(bytesToHex(k1a)).not.toBe(bytesToHex(k2))
    // 私钥在 secp256k1 范围内（BIP-32 派生保证）
    expect(k1a.length).toBe(32)
  })

  it('助记词 → 私钥全链派生（seed→BIP-32 m/44\'/60\'/0\'/0/0）', () => {
    const entropy = new Uint8Array(32).fill(9)
    const mnemonic = entropyToMnemonic(entropy)
    const priv = derivePrivateKeyFromMnemonic(mnemonic)
    expect(priv.length).toBe(32)
  })

  it('isLikelyMnemonic：24 词 true / 12 词 false / 垃圾 false', () => {
    const entropy = new Uint8Array(32).fill(3)
    const mnemonic = entropyToMnemonic(entropy)
    expect(isLikelyMnemonic(mnemonic)).toBe(true)
    expect(isLikelyMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon')).toBe(false)
    expect(isLikelyMnemonic('not a mnemonic at all not a mnemonic at all not a mnemonic at all')).toBe(false)
  })
})
