/**
 * WalletVault — 签名守护进程核心（唯一持钥者）
 *
 * 职责：
 * - 用 threshold 个分片解锁私钥（内存中组合，用完 wipe 清零）
 * - EIP-191 消息签名
 * - 拒绝暴露私钥：signMessage 是唯一对外签名入口
 *
 * 安全边界：本类是进程内唯一持有私钥明文的组件；MCP 与 signer 当前同进程
 * （凭证不进 LLM；独立无密钥 MCP 进程为路线图 P0-3）。
 */
import { secp256k1 } from '@noble/curves/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3'
import type { Share } from '@wallet-services/core'

/** EIP-191 前缀消息哈希 */
function personalMessageHash(message: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${message.length}`)
  const payload = new Uint8Array(prefix.length + message.length)
  payload.set(prefix)
  payload.set(message, prefix.length)
  return keccak_256(payload)
}

/** secp256k1 曲线阶 n（私钥必须 < n，组合结果校验） */
const CURVE_ORDER = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')

/** 私钥有效性校验（0 < priv < n），无效抛错防静默坏签名 */
function assertValidPrivateKey(priv: Uint8Array): void {
  const value = BigInt('0x' + Array.from(priv).map((b) => b.toString(16).padStart(2, '0')).join(''))
  if (value <= 0n || value >= CURVE_ORDER) {
    throw new Error('组合出的私钥无效（恢复码可能不匹配或已损坏）')
  }
}

export class WalletVault {
  private privKey: Uint8Array | null = null

  /** 当前是否已解锁 */
  get unlocked(): boolean {
    return this.privKey !== null
  }

  /** 注入已组合/已派生的账户私钥（O4A：命令层完成 熵组合→BIP-39/44 派生；
   * 旧 unlock(shares) 已移除——分片对象为熵，组合结果不可直接作私钥） */
  unlockPrivateKey(privateKey: Uint8Array): void {
    if (this.privKey) this.wipe()
    assertValidPrivateKey(privateKey)
    this.privKey = privateKey
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
