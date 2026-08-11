import { describe, it, expect } from 'bun:test'
import { secp256k1 } from '@noble/curves/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3'
import { WalletVault } from '../src/vault'

const PRIV = new Uint8Array(32)
PRIV[31] = 1 // 私钥 = 0x...01 → 已知地址 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf


function recoverAddress(message: Uint8Array, sig: Uint8Array): string {
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${message.length}`)
  const payload = new Uint8Array(prefix.length + message.length)
  payload.set(prefix)
  payload.set(message, prefix.length)
  const hash = keccak_256(payload)
  const pub = secp256k1.Signature.fromCompact(sig.slice(0, 64))
    .addRecoveryBit(sig[64])
    .recoverPublicKey(hash)
    .toRawBytes(false)
  const addrHash = keccak_256(pub.slice(1))
  return `0x${Array.from(addrHash.slice(12)).map((b) => b.toString(16).padStart(2, '0')).join('')}`
}

describe('WalletVault', () => {
  it('注入私钥 → 地址与已知向量一致', () => {
    const vault = new WalletVault()
    vault.unlockPrivateKey(new Uint8Array(PRIV))
    expect(vault.getAddress()).toBe('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')
    vault.wipe()
  })

  it('未解锁时签名抛错', () => {
    const vault = new WalletVault()
    expect(() => vault.signMessage(new TextEncoder().encode('hello'))).toThrow(/locked/)
  })

  it('EIP-191 签名可被验签还原出同一地址（闭环）', () => {
    const vault = new WalletVault()
    vault.unlockPrivateKey(new Uint8Array(PRIV))
    const msg = new TextEncoder().encode('bind wallet for envoytask-user-42')
    const sig = vault.signMessage(msg)
    expect(sig.length).toBe(65)
    const recovered = recoverAddress(msg, sig)
    expect(recovered.toLowerCase()).toBe(vault.getAddress().toLowerCase())
    vault.wipe()
  })

  it('wipe 后立即锁定（再次签名抛错）', () => {
    const vault = new WalletVault()
    vault.unlockPrivateKey(new Uint8Array(PRIV))
    expect(vault.unlocked).toBe(true)
    vault.wipe()
    expect(vault.unlocked).toBe(false)
    expect(() => vault.signMessage(new TextEncoder().encode('x'))).toThrow(/locked/)
  })

  it('重复注入自动清理旧私钥', () => {
    const vault = new WalletVault()
    vault.unlockPrivateKey(new Uint8Array(PRIV))
    const addr1 = vault.getAddress()
    vault.unlockPrivateKey(new Uint8Array(PRIV))
    expect(vault.getAddress()).toBe(addr1)
    vault.wipe()
  })
})
