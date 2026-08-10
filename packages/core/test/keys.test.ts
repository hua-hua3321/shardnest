import { describe, it, expect } from 'bun:test'
import {
  generatePrivateKey,
  privateKeyToAddress,
  generateKeyPair,
  deriveKEK,
} from '../src/keys'

/** 32 字节私钥：最后字节 = value */
function priv(value: number): Uint8Array {
  const bytes = new Uint8Array(32)
  bytes[31] = value
  return bytes
}

const CURVE_ORDER = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')

describe('私钥生成', () => {
  it('生成 32 字节且 < 曲线阶 n', () => {
    for (let i = 0; i < 20; i++) {
      const key = generatePrivateKey()
      expect(key.length).toBe(32)
      const v = BigInt('0x' + Buffer.from(key).toString('hex'))
      expect(v).toBeGreaterThan(0n)
      expect(v).toBeLessThan(CURVE_ORDER)
    }
  })

  it('两次生成结果不同（CSPRNG 随机性）', () => {
    const a = generatePrivateKey()
    const b = generatePrivateKey()
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false)
  })
})

describe('EVM 地址派生（已知测试向量）', () => {
  it('私钥 0x01 → 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf', () => {
    expect(privateKeyToAddress(priv(1))).toBe('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')
  })

  it('私钥 0x02 → 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF', () => {
    expect(privateKeyToAddress(priv(2))).toBe('0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF')
  })

  it('私钥 0x03 → 0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69', () => {
    expect(privateKeyToAddress(priv(3))).toBe('0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69')
  })

  it('地址为 0x + 40 位十六进制', () => {
    const { address } = generateKeyPair()
    expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/)
  })

  it('generateKeyPair 公私钥与地址自洽', () => {
    const kp = generateKeyPair()
    expect(privateKeyToAddress(kp.privateKey)).toBe(kp.address)
  })
})

describe('KEK 派生（scrypt）', () => {
  const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])

  it('输出 32 字节', async () => {
    const kek = await deriveKEK('correct horse battery staple', salt)
    expect(kek.length).toBe(32)
  })

  it('确定性：同口令同盐 → 同 KEK', async () => {
    const a = await deriveKEK('test-passphrase-1', salt)
    const b = await deriveKEK('test-passphrase-1', salt)
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true)
  })

  it('口令不同 → KEK 不同', async () => {
    const a = await deriveKEK('passphrase-A', salt)
    const b = await deriveKEK('passphrase-B', salt)
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false)
  })

  it('盐不同 → KEK 不同', async () => {
    const salt2 = new Uint8Array([9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9])
    const a = await deriveKEK('same-passphrase', salt)
    const b = await deriveKEK('same-passphrase', salt2)
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false)
  })
})
