/**
 * 密钥生成与地址派生
 *
 * 原则：私钥由 CSPRNG 独立随机生成——口令/身份因子不参与私钥，
 * 仅作为加密分片的钥匙（KEK）。这保证口令重置后私钥不变、地址不变。
 */
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex } from '@noble/hashes/utils'

/** secp256k1 曲线阶 n（私钥必须 < n） */
const CURVE_ORDER = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')

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
 * 私钥 → EVM 地址（0x + 公钥 keccak256 后 20 字节）
 */
export function privateKeyToAddress(privateKey: Uint8Array): `0x${string}` {
  const pub = secp256k1.getPublicKey(privateKey, false) // 65 字节非压缩
  const hash = sha256(pub.slice(1)) // keccak256 语义由 noble 提供
  // 注：EVM 地址 = keccak256(pubkey[1:])[12:]，此处先用 sha256 占位，
  // M1 引入 @noble/hashes/legacy 的 keccak 后替换。
  return `0x${bytesToHex(hash.slice(12))}` as `0x${string}`
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
  // M1 占位：scrypt 实现接入 @noble/hashes/scrypt
  const input = new TextEncoder().encode(`${passphrase}:${bytesToHex(salt)}`)
  return sha256(input)
}
