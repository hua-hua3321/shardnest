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

  it('W15：BIP-44 标准地址固化——MetaMask 兼容性守护（全零熵助记词）', () => {
    const { privateKeyToAddress } = require('../src/keys') as typeof import('../src/keys')
    // BIP-39 官方向量：32 字节全零熵 → 24 词（首 abandon…尾 art，校验和已验证）
    const mnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art'
    const priv = derivePrivateKeyFromMnemonic(mnemonic)
    const addr = privateKeyToAddress(priv)
    // 固化地址由双独立路径交叉验证一致（项目封装链 vs @scure/bip39+@scure/bip32 直接调用）：
    //   0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb
    // 若未来在 MetaMask 实测不同（说明 BIP44_PATH / seed 密码 / HDKey 用法被改动），
    // 更新此值前必须先定位根因——本断言守护 m/44'/60'/0'/0/0 与空 passphrase 语义
    expect(addr.toLowerCase()).toBe('0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb'.toLowerCase())
    // 双路径一致性（防封装层漂移）：直接库调用派生同一地址
    const { mnemonicToSeedSync } = require('@scure/bip39') as typeof import('@scure/bip39')
    const { HDKey } = require('@scure/bip32') as typeof import('@scure/bip32')
    const seed = mnemonicToSeedSync(mnemonic, '')
    try {
      const hd = HDKey.fromMasterSeed(seed)
      const child = hd.derive("m/44'/60'/0'/0/0")
      expect(child.privateKey).toBeTruthy()
      expect(privateKeyToAddress(child.privateKey!).toLowerCase()).toBe(addr.toLowerCase())
    } finally {
      seed.fill(0)
    }
  })

  it('isLikelyMnemonic：24 词 true / 12 词 false / 垃圾 false', () => {
    const entropy = new Uint8Array(32).fill(3)
    const mnemonic = entropyToMnemonic(entropy)
    expect(isLikelyMnemonic(mnemonic)).toBe(true)
    expect(isLikelyMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon')).toBe(false)
    expect(isLikelyMnemonic('not a mnemonic at all not a mnemonic at all not a mnemonic at all')).toBe(false)
  })
})
