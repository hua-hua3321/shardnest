/**
 * verify-sdk — 平台侧验签 SDK（verify-only，无任何密钥逻辑）
 *
 * 用途：平台验证用户钱包返回的 EIP-191 签名（绑定钱包、提现确认等）。
 * 输入：message + 65 字节签名 (r||s||v) → 输出签名者地址
 */
import { secp256k1 } from '@noble/curves/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3'

function personalMessageHash(message: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${message.length}`)
  const payload = new Uint8Array(prefix.length + message.length)
  payload.set(prefix)
  payload.set(message, prefix.length)
  return keccak_256(payload)
}

function toChecksum(bytes: Uint8Array): `0x${string}` {
  const lower = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('').toLowerCase()
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
 * EIP-191 验签：还原签名者地址（EIP-55 checksum）
 * @param message 原始消息（与签名时一致）
 * @param signature 65 字节 (r||s||v)
 */
export function recoverSigner(message: string | Uint8Array, signature: Uint8Array): `0x${string}` {
  if (signature.length !== 65) throw new Error('signature must be 65 bytes (r||s||v)')
  const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message
  const hash = personalMessageHash(msg)
  const pub = secp256k1.Signature.fromCompact(signature.slice(0, 64))
    .addRecoveryBit(signature[64])
    .recoverPublicKey(hash)
    .toRawBytes(false)
  const addrHash = keccak_256(pub.slice(1))
  return toChecksum(addrHash.slice(12))
}

/**
 * 验签并断言签名者地址匹配期望地址
 */
export function verifySignature(message: string | Uint8Array, signature: Uint8Array, expectedAddress: string): boolean {
  const recovered = recoverSigner(message, signature)
  return recovered.toLowerCase() === expectedAddress.toLowerCase()
}
