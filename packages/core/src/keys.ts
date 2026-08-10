/**
 * 密钥生成与地址派生
 *
 * 原则：私钥由 CSPRNG 独立随机生成——口令/身份因子不参与私钥，
 * 仅作为加密分片的钥匙（KEK）。这保证口令重置后私钥不变、地址不变。
 */
import { secp256k1 } from '@noble/curves/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3'
import { scryptAsync } from '@noble/hashes/scrypt'
import { bytesToHex } from '@noble/hashes/utils'

/** secp256k1 曲线阶 n（私钥必须 < n） */
const CURVE_ORDER = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')

/** KEK 派生参数（scrypt 高成本防暴力破解；2^16=64MB 内存，兼顾 Web 端） */
const SCRYPT_OPTS = { N: 2 ** 16, r: 8, p: 1, dkLen: 32 }

export interface KeyPair {
  privateKey: Uint8Array
  publicKey: Uint8Array
  address: `0x${string}`
}

/**
 * CSPRNG 生成私钥（32 字节，校验 < 曲线阶 n，极端情况重试）
 */
export function generatePrivateKey(): Uint8Array {
  const bytes = new Uint8Array(32)
  for (;;) {
    crypto.getRandomValues(bytes)
    const value = BigInt('0x' + bytesToHex(bytes))
    if (value > 0n && value < CURVE_ORDER) return bytes
  }
}

/**
 * 私钥 → 公钥（33 字节压缩格式）
 */
export function privateKeyToPublicKey(privateKey: Uint8Array): Uint8Array {
  return secp256k1.getPublicKey(privateKey, true)
}

/**
 * EIP-55 checksum 地址（大小写校验和，防复制错误）
 */
export function toChecksumAddress(address: string): `0x${string}` {
  const lower = address.toLowerCase().replace(/^0x/, '')
  const hash = keccak_256(new TextEncoder().encode(lower))
  let result = '0x'
  for (let i = 0; i < lower.length; i++) {
    const byte = hash[i >> 1]
    const nibble = i % 2 === 0 ? byte >> 4 : byte & 0x0f
    result += nibble >= 8 ? lower[i].toUpperCase() : lower[i]
  }
  return result as `0x${string}`
}

/**
 * 私钥 → EVM 地址（EIP-55 checksum 格式）
 * 标准推导：address = keccak256(pubkey_uncompressed[1:])[12:]
 */
export function privateKeyToAddress(privateKey: Uint8Array): `0x${string}` {
  const pub = secp256k1.getPublicKey(privateKey, false) // 65 字节非压缩
  const hash = keccak_256(pub.slice(1))
  return toChecksumAddress(`0x${bytesToHex(hash.slice(12))}`)
}

/**
 * 生成完整密钥对（私钥 + 公钥 + 地址）
 */
export function generateKeyPair(): KeyPair {
  const privateKey = generatePrivateKey()
  const publicKey = privateKeyToPublicKey(privateKey)
  return { privateKey, publicKey, address: privateKeyToAddress(privateKey) }
}

/**
 * 口令派生 KEK（用于加密分片）——口令只在这里被使用，
 * 不参与私钥本身；scrypt 高成本参数防暴力破解。
 */
export async function deriveKEK(passphrase: string, salt: Uint8Array): Promise<Uint8Array> {
  const password = new TextEncoder().encode(passphrase)
  return scryptAsync(password, salt, SCRYPT_OPTS)
}
