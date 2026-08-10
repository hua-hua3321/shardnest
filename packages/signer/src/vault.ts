/**
 * WalletVault — 签名守护进程核心（唯一持钥者）
 *
 * 职责：
 * - 用 threshold 个分片解锁私钥（内存中组合，用完 wipe 清零）
 * - EIP-191 消息签名
 * - 拒绝暴露私钥：signMessage 是唯一对外签名入口
 *
 * 安全边界：本类是进程内唯一持有私钥明文的组件；MCP 薄壳无密钥。
 */
import { secp256k1 } from '@noble/curves/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3'
import { combineShares, type Share } from '@wallet-service/core'

/** EIP-191 前缀消息哈希 */
function personalMessageHash(message: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${message.length}`)
  const payload = new Uint8Array(prefix.length + message.length)
  payload.set(prefix)
  payload.set(message, prefix.length)
  return keccak_256(payload)
}

export class WalletVault {
  private privKey: Uint8Array | null = null

  /** 当前是否已解锁 */
  get unlocked(): boolean {
    return this.privKey !== null
  }

  /** 用任意 threshold 个分片解锁私钥（内存组合，用完调用 wipe） */
  unlock(shares: Share[]): void {
    if (this.privKey) this.wipe()
    this.privKey = combineShares(shares)
  }

  /** 私钥 → 地址（EIP-55 checksum） */
  getAddress(): `0x${string}` {
    if (!this.privKey) throw new Error('Vault is locked')
    const pub = secp256k1.getPublicKey(this.privKey, false)
    const hash = keccak_256(pub.slice(1))
    return toChecksum(hash.slice(12))
  }

  /**
   * EIP-191 个人消息签名，返回 65 字节 (r||s||v)
   */
  signMessage(message: Uint8Array): Uint8Array {
    if (!this.privKey) throw new Error('Vault is locked')
    const hash = personalMessageHash(message)
    const sig = secp256k1.sign(hash, this.privKey)
    const raw = sig.toCompactRawBytes() // 64 字节 r||s
    const out = new Uint8Array(65)
    out.set(raw)
    out[64] = sig.recovery ?? 0
    return out
  }

  /** 销毁内存中的私钥（用完必调） */
  wipe(): void {
    if (this.privKey) this.privKey.fill(0)
    this.privKey = null
  }
}

/** EIP-55 checksum（与 core 的 toChecksumAddress 一致，避免跨包依赖循环） */
function toChecksum(bytes: Uint8Array): `0x${string}` {
  const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
  const lower = hex.toLowerCase()
  const hash = keccak_256(new TextEncoder().encode(lower))
  let result = '0x'
  for (let i = 0; i < lower.length; i++) {
    const byte = hash[i >> 1]
    const nibble = i % 2 === 0 ? byte >> 4 : byte & 0x0f
    result += nibble >= 8 ? lower[i].toUpperCase() : lower[i]
  }
  return result as `0x${string}`
}
