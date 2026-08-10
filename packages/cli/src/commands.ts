/**
 * CLI 命令实现（可测试核心逻辑）
 *
 * 存储模型（~/.shardnest/，可用 SHARDNEST_HOME 覆盖）：
 * - metadata.json  明文：{ address, version }（地址非秘密）
 * - device-share.json  片①，口令加密（scrypt KEK + AES-GCM）
 * - 恢复码 = 片② + 片③（init/reshare 时打印，用户自行保存）
 *
 * 安全边界：本目录持有 1 片 + 用户脑中的口令；恢复码 2 片在用户手中。
 * 设备丢失 → 用恢复码②③ restore；口令丢失 → 恢复码②③ restore 后重设口令。
 */
import { promises as fs } from 'node:fs'
import * as path from 'node:path'
import {
  generateKeyPair,
  splitSecret,
  combineShares,
  reshareShares,
  deriveKEK,
  type Share,
} from '@wallet-service/core'
import { gcm } from '@noble/ciphers/aes'
import { randomBytes } from '@noble/hashes/utils'

/** 钱包目录（动态读取 env，便于测试隔离） */
export function getHomeDir(): string {
  return process.env.SHARDNEST_HOME ?? path.join(process.env.HOME ?? '.', '.shardnest')
}
const metaFile = () => path.join(getHomeDir(), 'metadata.json')
const deviceFile = () => path.join(getHomeDir(), 'device-share.json')

export interface InitResult {
  address: string
  recoveryCodes: string[] // 片② + 片③（用户保存）
}

/** 恢复码编码：sn1-<index>-<hex> */
export function encodeRecoveryCode(share: Share): string {
  return `sn1-${share.index}-${Buffer.from(share.bytes).toString('hex')}`
}

export function decodeRecoveryCode(code: string): Share {
  const [ver, idx, hex] = code.trim().split('-')
  if (ver !== 'sn1' || !idx || !hex) throw new Error('无效恢复码格式')
  return { index: Number(idx), bytes: new Uint8Array(Buffer.from(hex, 'hex')) }
}

async function encryptShare(share: Share, passphrase: string): Promise<{ data: string; salt: string }> {
  const salt = randomBytes(16)
  const kek = await deriveKEK(passphrase, salt)
  const nonce = randomBytes(12)
  const cipher = gcm(kek, nonce)
  const payload = new Uint8Array(1 + share.bytes.length)
  payload[0] = share.index
  payload.set(share.bytes, 1)
  const ct = cipher.encrypt(payload)
  return {
    data: Buffer.from(nonce).toString('base64') + '.' + Buffer.from(ct).toString('base64'),
    salt: Buffer.from(salt).toString('base64'),
  }
}

async function decryptShare(enc: { data: string; salt: string }, passphrase: string): Promise<Share> {
  const salt = Uint8Array.from(Buffer.from(enc.salt, 'base64'))
  const kek = await deriveKEK(passphrase, salt)
  const [nonceB64, ctB64] = enc.data.split('.')
  const nonce = Uint8Array.from(Buffer.from(nonceB64, 'base64'))
  const ct = Uint8Array.from(Buffer.from(ctB64, 'base64'))
  const cipher = gcm(kek, nonce)
  const payload = cipher.decrypt(ct)
  return { index: payload[0], bytes: payload.slice(1) }
}

/** 初始化：生成密钥对 → 2-of-3 分片 → 片①口令加密存设备 → 返回恢复码②③ */
export async function initWallet(passphrase: string): Promise<InitResult> {
  const { privateKey, address } = generateKeyPair()
  const shares = splitSecret(privateKey, { shares: 3, threshold: 2 })
  const enc = await encryptShare(shares[0], passphrase)

  await fs.mkdir(getHomeDir(), { recursive: true })
  await fs.writeFile(metaFile(), JSON.stringify({ version: 1, address }, null, 2), { mode: 0o600 })
  await fs.writeFile(deviceFile(), JSON.stringify({ version: 1, share: enc }, null, 2), { mode: 0o600 })

  // 内存清零
  privateKey.fill(0)
  return { address, recoveryCodes: [shares[1], shares[2]].map(encodeRecoveryCode) }
}

/** 显示地址（无需口令） */
export async function getAddress(): Promise<string> {
  const meta = JSON.parse(await fs.readFile(metaFile(), 'utf8')) as { address: string }
  return meta.address
}

/** 解锁并签名：口令解锁设备片① + 用户提供 1 个恢复码 → EIP-191 签名 */
export async function signMessage(passphrase: string, recoveryCode: string, message: string): Promise<string> {
  const enc = JSON.parse(await fs.readFile(deviceFile(), 'utf8')) as { share: { data: string; salt: string } }
  const share1 = await decryptShare(enc.share, passphrase)
  const share2 = decodeRecoveryCode(recoveryCode)
  const { WalletVault } = await import('@wallet-service/signer')
  const vault = new WalletVault()
  vault.unlock([share1, share2])
  const sig = vault.signMessage(new TextEncoder().encode(message))
  const addr = vault.getAddress()
  vault.wipe()
  return JSON.stringify({ address: addr, signature: Buffer.from(sig).toString('hex') })
}

/** 恢复：输入任意 2 个恢复码 → 重组 → 新设备片（口令加密）+ 新恢复码（reshare） */
export async function restoreWallet(passphrase: string, recoveryCodes: [string, string]): Promise<InitResult> {
  const shares = recoveryCodes.map(decodeRecoveryCode)
  const fresh = reshareShares(shares, { shares: 3, threshold: 2 })
  const enc = await encryptShare(fresh[0], passphrase)
  const privateKey = combineShares([fresh[0], fresh[1]])
  const { privateKeyToAddress } = await import('@wallet-service/core')
  const address = privateKeyToAddress(privateKey)
  privateKey.fill(0)

  await fs.mkdir(getHomeDir(), { recursive: true })
  await fs.writeFile(metaFile(), JSON.stringify({ version: 1, address }, null, 2), { mode: 0o600 })
  await fs.writeFile(deviceFile(), JSON.stringify({ version: 1, share: enc }, null, 2), { mode: 0o600 })

  return { address, recoveryCodes: [fresh[1], fresh[2]].map(encodeRecoveryCode) }
}
