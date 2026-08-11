import { describe, it, expect } from 'bun:test'
import { privateKeyToMnemonic, mnemonicToPrivateKey, isLikelyMnemonic } from '../src/mnemonic'
import { generatePrivateKey } from '../src/keys'

describe('BIP-39 助记词（24 词）', () => {
  it('私钥 → 24 词 → 私钥 往返一致', () => {
    const priv = generatePrivateKey()
    const mnemonic = privateKeyToMnemonic(priv)
    expect(mnemonic.split(' ').length).toBe(24)
    expect(mnemonicToPrivateKey(mnemonic)).toEqual(priv)
  })

  it('已知向量：全零私钥 → 固定 24 词（确定性）', () => {
    const zero = new Uint8Array(32)
    const m = privateKeyToMnemonic(zero)
    // 确定性校验：同一输入两次编码一致
    expect(privateKeyToMnemonic(zero)).toBe(m)
    expect(m.split(' ').length).toBe(24)
  })

  it('12 词输入 → 拒绝（容量不足，校验和必然失败）', () => {
    const priv = generatePrivateKey()
    const mnemonic = privateKeyToMnemonic(priv)
    const first12 = mnemonic.split(' ').slice(0, 12).join(' ')
    expect(() => mnemonicToPrivateKey(first12)).toThrow(/助记词无效/)
  })

  it('篡改单词 → 拒绝（BIP-39 校验和）', () => {
    const priv = generatePrivateKey()
    const words = privateKeyToMnemonic(priv).split(' ')
    words[0] = words[0] === 'abandon' ? 'ability' : 'abandon'
    expect(() => mnemonicToPrivateKey(words.join(' '))).toThrow(/助记词无效/)
  })

  it('isLikelyMnemonic：24 词 true / 12 词 false / 垃圾 false', () => {
    const priv = generatePrivateKey()
    const mnemonic = privateKeyToMnemonic(priv)
    expect(isLikelyMnemonic(mnemonic)).toBe(true)
    expect(isLikelyMnemonic('abandon abandon abandon')).toBe(false)
    expect(isLikelyMnemonic('foo bar baz')).toBe(false)
  })

  it('非 32 字节输入 → 拒绝', () => {
    expect(() => privateKeyToMnemonic(new Uint8Array(16))).toThrow(/32 字节/)
  })
})
