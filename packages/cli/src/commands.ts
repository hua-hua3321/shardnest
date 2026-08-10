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
import { sendBackupShare } from './mailer'
import { createUnlockSession } from '@wallet-service/signer'
import { randomBytes } from '@noble/hashes/utils'

/** 钱包目录（动态读取 env，便于测试隔离） */
export function getHomeDir(): string {
  return process.env.SHARDNEST_HOME ?? path.join(process.env.HOME ?? '.', '.shardnest')
}
const metaFile = () => path.join(getHomeDir(), 'metadata.json')
const deviceFile = () => path.join(getHomeDir(), 'device-share.json')
const recoveryFile = () => path.join(getHomeDir(), 'recovery-codes.txt')

/** 恢复码落盘（0600 明文，用户自持责任；与纸备份等价，供 MCP 场景免 LLM 交付） */
export async function saveRecoveryCodes(codes: string[]): Promise<string> {
  const file = recoveryFile()
  const content = [
    '# shardnest 恢复码（请妥善保管，勿转发/上传）',
    '# 任意 2 个可恢复钱包；单凭 1 个无法动用资金',
    '',
    ...codes.map((c) => c + ''),
  ].join('\n') + '\n'
  await fs.writeFile(file, content, { mode: 0o600 })
  return file
}

export interface InitResult {
  address: string
  recoveryCodes: string[] // 片② + 片③（用户保存）
  /** 邮箱备份分片状态（提供邮箱时）：sent=已发送 / skipped=未配置 SMTP */
  backupEmail?: string
  backupStatus?: 'sent' | 'skipped'
  /** 恢复码本地文件路径（MCP 场景经此交付，不经 LLM） */
  recoveryFile?: string
  /** 附加提示（如 restore 后需更新邮箱备份） */
  note?: string
}

import { keccak_256 } from '@noble/hashes/sha3'

/** 恢复码编码：sn1-<index>-<hex>-<crc>
 * crc = keccak(`${index}:${hex}`) 首字节——CRC 覆盖 index+hex，
 * 防手输/OCR 错误的同时杜绝「错误 index + 正确 hex」绕过（P1-B）
 */
export function encodeRecoveryCode(share: Share): string {
  const hex = Buffer.from(share.bytes).toString('hex')
  const crc = keccak_256(new TextEncoder().encode(`${share.index}:${hex}`))[0].toString(16).padStart(2, '0')
  return `sn1-${share.index}-${hex}-${crc}`
}

export function decodeRecoveryCode(code: string): Share {
  const parts = code.trim().split('-')
  if (parts.length !== 4 || parts[0] !== 'sn1') throw new Error('无效恢复码格式')
  const [, idx, hex, crc] = parts
  const index = Number(idx)
  // index 必须为 [1,255] 整数（GF(256) x 坐标域）
  if (!Number.isInteger(index) || index < 1 || index > 255) throw new Error('恢复码 index 超出有效范围')
  if (!/^[0-9a-f]{2,128}$/.test(hex) || hex.length % 2 !== 0) throw new Error('恢复码 hex 格式无效')
  const expectCrc = keccak_256(new TextEncoder().encode(`${index}:${hex}`))[0].toString(16).padStart(2, '0')
  if (crc !== expectCrc) throw new Error('恢复码校验失败（可能抄错/损坏），请核对后重试')
  return { index, bytes: new Uint8Array(Buffer.from(hex, 'hex')) }
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

/** 口令强度校验（≥12 位，防弱口令爆破设备分片） */
export function validatePassphrase(passphrase: string): void {
  if (passphrase.length < 12) {
    throw new Error('口令至少 12 位（建议混合大小写/数字/符号）')
  }
}

/** 初始化：生成密钥对 → 2-of-3 分片 → 片①口令加密存设备 → 返回恢复码②③
 * 提供 email 时：自动将片③（备份分片）发送到邮箱（SMTP 未配置则 skipped）
 * 原子性：先完成所有可失败操作（含邮件发送）→ 最后落盘，失败不留下半成品
 */
export async function initWallet(passphrase: string, email?: string): Promise<InitResult> {
  validatePassphrase(passphrase)
  const { privateKey, address } = generateKeyPair()
  const shares = splitSecret(privateKey, { shares: 3, threshold: 2 })
  const enc = await encryptShare(shares[0], passphrase)
  const recoveryCodes = [shares[1], shares[2]].map(encodeRecoveryCode)

  // 1. 可失败操作先行：邮箱校验 + 发送（失败抛错 → 不落盘）
  let backupStatus: 'sent' | 'skipped' | undefined
  if (email) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      throw new Error('邮箱格式无效')
    }
    backupStatus = await sendBackupShare(email, address, recoveryCodes[1])
  }

  // 2. 全部成功后原子落盘
  await fs.mkdir(getHomeDir(), { recursive: true })
  await fs.writeFile(metaFile(), JSON.stringify({ version: 1, address }, null, 2), { mode: 0o600 })
  await fs.writeFile(deviceFile(), JSON.stringify({ version: 1, share: enc }, null, 2), { mode: 0o600 })
  privateKey.fill(0)

  // 恢复码落盘（0600，用户自持；MCP 场景经此交付不经 LLM）
  const recoveryFileWritten = await saveRecoveryCodes(recoveryCodes)
  return { address, recoveryCodes, backupEmail: email, backupStatus, recoveryFile: recoveryFileWritten }
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
  try {
    const { WalletVault } = await import('@wallet-service/signer')
    const vault = new WalletVault()
    vault.unlock([share1, share2])
    const sig = vault.signMessage(new TextEncoder().encode(message))
    const addr = vault.getAddress()
    vault.wipe()
    return JSON.stringify({ address: addr, signature: Buffer.from(sig).toString('hex') })
  } finally {
    share1.bytes.fill(0)
    share2.bytes.fill(0)
  }
}

/** 恢复：输入任意 2 个恢复码 → 重组 → 新设备片（口令加密）+ 新恢复码（reshare）
 * 地址交叉校验（P1-1）：旧 metadata 存在或提供 expectedAddress 时，恢复地址
 * 不一致立即报错——防止输错恢复码静默恢复出「错误钱包」
 */
export async function restoreWallet(
  passphrase: string,
  recoveryCodes: [string, string],
  expectedAddress?: string,
): Promise<InitResult> {
  validatePassphrase(passphrase)
  const shares = recoveryCodes.map(decodeRecoveryCode)
  const fresh = reshareShares(shares, { shares: 3, threshold: 2 })
  const enc = await encryptShare(fresh[0], passphrase)
  const privateKey = combineShares([fresh[0], fresh[1]])
  const { privateKeyToAddress } = await import('@wallet-service/core')
  const address = privateKeyToAddress(privateKey)
  privateKey.fill(0)

  // 地址交叉校验：期望地址 or 旧 metadata 地址
  const want = expectedAddress ?? (await readOldAddress())
  if (want && want.toLowerCase() !== address.toLowerCase()) {
    throw new Error(`恢复出的地址 (${address}) 与目标地址 (${want}) 不一致——恢复码可能输错，操作已中止`)
  }

  await fs.mkdir(getHomeDir(), { recursive: true })
  await fs.writeFile(metaFile(), JSON.stringify({ version: 1, address }, null, 2), { mode: 0o600 })
  try {
    await fs.writeFile(deviceFile(), JSON.stringify({ version: 1, share: enc }, null, 2), { mode: 0o600 })
  } catch (err) {
    await fs.rm(metaFile(), { force: true }) // 回滚：不留下半成品
    throw err
  }

  const newCodes = [fresh[1], fresh[2]].map(encodeRecoveryCode)
  const recoveryFileWritten = await saveRecoveryCodes(newCodes)
  return {
    address,
    recoveryCodes: newCodes,
    recoveryFile: recoveryFileWritten,
    note: '如曾使用邮箱备份，请重新运行 init 邮箱流程更新邮箱中的备份分片（旧邮件中的分片仍有效，建议删除）',
  }
}

/** 创建解锁令牌：本地口令+恢复码 → 组合私钥 → 短期单次解锁会话（P0-1） */
export async function createUnlockToken(passphrase: string, recoveryCode: string): Promise<string> {
  const enc = JSON.parse(await fs.readFile(deviceFile(), 'utf8')) as { share: { data: string; salt: string } }
  const share1 = await decryptShare(enc.share, passphrase)
  const share2 = decodeRecoveryCode(recoveryCode)
  try {
    const privateKey = combineShares([share1, share2])
    const token = await createUnlockSession(privateKey)
    privateKey.fill(0)
    return token
  } finally {
    share1.bytes.fill(0)
    share2.bytes.fill(0)
  }
}

/** 读取旧 metadata 中的地址（不存在返回 undefined） */
async function readOldAddress(): Promise<string | undefined> {
  try {
    const meta = JSON.parse(await fs.readFile(metaFile(), 'utf8')) as { address?: string }
    return meta.address
  } catch {
    return undefined
  }
}
