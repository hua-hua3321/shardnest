/**
 * 密钥生成与地址派生
 *
 * 原则：私钥由 CSPRNG 独立随机生成——口令/身份因子不参与私钥，
 * 仅作为加密分片的钥匙（KEK）。这保证口令重置后私钥不变、地址不变。
 */
import { secp256k1 } from '@noble/curves/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3'
import { scryptAsync } from '@noble/hashes/scrypt'
import { bytesToHex, randomBytes } from '@noble/hashes/utils'

/** secp256k1 曲线阶 n（私钥必须 < n） */
const CURVE_ORDER = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')

/** KEK 派生参数（scrypt 高成本防暴力破解；O1 起随密文持久化，可平滑升级） */
export const SCRYPT_OPTS = { N: 2 ** 18, r: 8, p: 1, dkLen: 32 } as const // P1-4: 提升至 256MB（仍为 OWASP 量级，远小于上限 2^20=1GiB）；旧钱包 KDF 参数随密文持久化，向后兼容

/** v1 历史参数（C1：无 kdf 字段的旧钱包仅可能以 2^16 加密——回退必须用它而非新默认） */
export const LEGACY_SCRYPT_OPTS_V1 = { N: 2 ** 16, r: 8, p: 1, dkLen: 32 } as const

/** scrypt 参数上限（中风险: 防篡改 device-share.json 的 KDF 元数据导致内存/CPU DoS） */
export const SCRYPT_PARAM_CAPS = {
  N_MAX: 2 ** 20, // 1 GiB——超限即拒绝（合法值远小于此）
  R_MAX: 64,
  P_MAX: 32,
  DK_LEN_MAX: 64,
} as const

/** 持久化到密文的 KDF 元数据（RFC 8018 / age / 1Password 同款实践） */
export interface KdfParams {
  alg: 'scrypt'
  N: number
  r: number
  p: number
  dkLen: number
}

/** 构造 KDF 参数（含上限校验：非法/超限参数抛错，防资源耗尽） */
export function kdfParamsOf(opts?: Partial<KdfParams>): KdfParams {
  const N = opts?.N ?? SCRYPT_OPTS.N
  const r = opts?.r ?? SCRYPT_OPTS.r
  const p = opts?.p ?? SCRYPT_OPTS.p
  const dkLen = opts?.dkLen ?? SCRYPT_OPTS.dkLen
  const cap = SCRYPT_PARAM_CAPS
  if (opts?.alg !== undefined && opts.alg !== 'scrypt') throw new Error('不支持的 KDF 算法')
  if (!Number.isInteger(N) || N < 2 ** 12 || N > cap.N_MAX || (N & (N - 1)) !== 0) throw new Error('非法 scrypt N 参数（须为 [4096, 2^20] 的 2 的幂）')
  if (!Number.isInteger(r) || r < 1 || r > cap.R_MAX) throw new Error('非法 scrypt r 参数')
  if (!Number.isInteger(p) || p < 1 || p > cap.P_MAX) throw new Error('非法 scrypt p 参数')
  if (!Number.isInteger(dkLen) || dkLen < 16 || dkLen > cap.DK_LEN_MAX) throw new Error('非法 scrypt dkLen 参数')
  return { alg: 'scrypt', N, r, p, dkLen }
}

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
/** 生成钱包根熵（32 字节 CSPRNG；O4A：分片对象=熵，助记词=熵的可逆编码） */
export function generateEntropy(): Uint8Array {
  return randomBytes(32)
}

export function generateKeyPair(): KeyPair {
  const privateKey = generatePrivateKey()
  const publicKey = privateKeyToPublicKey(privateKey)
  return { privateKey, publicKey, address: privateKeyToAddress(privateKey) }
}

/**
 * 口令派生 KEK（用于加密分片）——口令只在这里被使用，
 * 不参与私钥本身；scrypt 高成本参数防暴力破解。
 */
/** 派生 KEK：参数可注入（O1——解密时使用密文中持久化的 KDF 参数，而非当前常量） */
export async function deriveKEK(passphrase: string, salt: Uint8Array, opts?: Partial<KdfParams>): Promise<Uint8Array> {
  const password = new TextEncoder().encode(passphrase)
  try {
    return await scryptAsync(password, salt, kdfParamsOf(opts))
  } finally {
    password.fill(0) // 中风险: 口令字节用后清零（不变式 5 精神）
  }
}
