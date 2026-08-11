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
import { createUnlockSession, getUnlockDir } from '@wallet-service/signer'
import { randomBytes } from '@noble/hashes/utils'
import { privateKeyToMnemonic, mnemonicToPrivateKey } from '@wallet-service/core'

/** 钱包目录（动态读取 env，便于测试隔离） */
export function getHomeDir(): string {
  return process.env.SHARDNEST_HOME ?? path.join(process.env.HOME ?? '.', '.shardnest')
}
const metaFile = () => path.join(getHomeDir(), 'metadata.json')
const deviceFile = () => path.join(getHomeDir(), 'device-share.json')
const recoveryFile = () => path.join(getHomeDir(), 'recovery-codes.txt')
const mnemonicFile = () => path.join(getHomeDir(), 'mnemonic.txt')

/** 助记词落盘（0600；助记词=完整私钥，用户选择生成即接受单点保管） */
export async function saveMnemonic(mnemonic: string): Promise<string> {
  const file = mnemonicFile()
  await fs.mkdir(path.dirname(file), { recursive: true })
  const content = [
    '# shardnest 24 词助记词备份（完整私钥，单点！请勿拍照/截图/网络传输）',
    '# 单凭此 24 词即可恢复钱包；泄露即资金丢失（与分片恢复码不同，无门限保护）',
    '',
    mnemonic,
    '',
  ].join('\n') + '\n'
  await fs.writeFile(file, content, { mode: 0o600 })
  return file
}

/** 恢复码落盘（0600 明文，用户自持责任；与纸备份等价，供 MCP 场景免 LLM 交付）
 * 存储策略（方案 A+B）：
 * - 邮箱发送成功（1 片本地）→ 本地仅存 1 片，头部说明另一片在邮箱——本机整体失守无法动钱
 * - 未发邮箱（2 片本地）→ 显著警告：本地集中 2 片=私钥，整体泄露即失守，建议转移/配邮箱
 */
export async function saveRecoveryCodes(codes: string[], emailed = false): Promise<string> {
  const file = recoveryFile()
  await fs.mkdir(path.dirname(file), { recursive: true })
  const header = emailed
    ? [
        '# shardnest 恢复码（本地仅 1 片）',
        '# 另一片已发送至您的邮箱——本机目录整体泄露也无法动用资金',
        '# 请妥善保管邮箱备份；任意 2 片（含邮箱片）可恢复钱包',
      ]
    : [
        '# shardnest 恢复码（⚠️ 2 片均在本机！）',
        '# 任意 2 片可重组私钥——本目录整体泄露 = 资金丢失（无需口令）',
        '# 强烈建议：转移 1 片离线保存（纸/密码管理器），或重新 init 配置邮箱备份',
        '# 单凭 1 片无法动用资金',
      ]
  const content = [...header, '', ...codes.map((c) => c + '')].join('\n') + '\n'
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
  /** 24 词助记词文件路径（用户选择生成时；助记词=完整私钥，经文件交付不经 LLM） */
  mnemonicFile?: string
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
 * mnemonic=true 时：同步生成 24 词助记词（完整私钥备份，可单独恢复；默认关闭）
 * 原子性：先完成所有可失败操作（邮件/恢复码/助记词落盘）→ 最后落盘，失败不留下半成品
 */
export async function initWallet(passphrase: string, email?: string, mnemonic = false): Promise<InitResult> {
  validatePassphrase(passphrase)
  const { privateKey, address } = generateKeyPair()
  return createWalletFromPrivateKey(passphrase, privateKey, email, mnemonic)
}

/** 从既定私钥建钱包（init 与助记词恢复共用；调用方负责 privateKey 清零） */
async function createWalletFromPrivateKey(
  passphrase: string,
  privateKey: Uint8Array,
  email?: string,
  mnemonic = false,
): Promise<InitResult> {
  const { privateKeyToAddress } = await import('@wallet-service/core')
  const address = privateKeyToAddress(privateKey)
  const shares = splitSecret(privateKey, { shares: 3, threshold: 2 })
  const enc = await encryptShare(shares[0], passphrase)
  const recoveryCodes = [shares[1], shares[2]].map(encodeRecoveryCode)

  // 1. 可失败操作先行：邮箱校验 + 发送（失败抛错 → 不落盘）
  let backupStatus: 'sent' | 'skipped' | undefined
  if (email) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      privateKey.fill(0)
      throw new Error('邮箱格式无效')
    }
    backupStatus = await sendBackupShare(email, address, recoveryCodes[1])
  }

  // 2. 可失败操作全部前置（恢复码/助记词落盘）
  //    存储策略 A+B：邮箱已送达（sent）→ 本地只存片②（片③在邮箱，三处分布）；
  //    skipped/无邮箱 → 本地存 2 片（显著警告，用户自担）
  const emailed = backupStatus === 'sent'
  const localCodes = emailed ? [recoveryCodes[0]] : recoveryCodes
  const recoveryFileWritten = await saveRecoveryCodes(localCodes, emailed)
  let mnemonicFileWritten: string | undefined
  if (mnemonic) {
    mnemonicFileWritten = await saveMnemonic(privateKeyToMnemonic(privateKey))
  }

  // 3. 原子落盘 + 回滚（失败时清理全部已写文件——含明文恢复码/助记词=私钥材料）
  try {
    await fs.mkdir(getHomeDir(), { recursive: true })
    await fs.writeFile(metaFile(), JSON.stringify({ version: 1, address }, null, 2), { mode: 0o600 })
    await fs.writeFile(deviceFile(), JSON.stringify({ version: 1, share: enc }, null, 2), { mode: 0o600 })
  } catch (err) {
    await fs.rm(metaFile(), { force: true })
    await fs.rm(deviceFile(), { force: true })
    await fs.rm(recoveryFileWritten, { force: true }) // 明文恢复码（2 片=私钥）
    if (mnemonicFileWritten) await fs.rm(mnemonicFileWritten, { force: true }) // 助记词=完整私钥
    throw err
  } finally {
    privateKey.fill(0) // 所有路径（成功/异常）均清零
  }

  return {
    address,
    recoveryCodes,
    backupEmail: email,
    backupStatus,
    recoveryFile: recoveryFileWritten,
    mnemonicFile: mnemonicFileWritten,
    note: mnemonic
      ? '助记词已生成（=完整私钥，单点）：请抄写并安全保管，勿拍照/截图/网络传输；建议抄写离线保存后执行 wipe 删除本机明文备份'
      : undefined,
  }
}

/** 从 24 词助记词单独恢复（绕过 2-of-3；重建分片/设备片/恢复码，地址交叉校验） */
export async function restoreFromMnemonic(
  passphrase: string,
  mnemonic: string,
  expectedAddress?: string,
  email?: string,
): Promise<InitResult> {
  validatePassphrase(passphrase)
  const privateKey = mnemonicToPrivateKey(mnemonic)
  try {
    const { privateKeyToAddress } = await import('@wallet-service/core')
    const address = privateKeyToAddress(privateKey)

    const want = expectedAddress ?? (await readOldAddress())
    if (want && want.toLowerCase() !== address.toLowerCase()) {
      throw new Error(`助记词恢复出的地址 (${address}) 与目标地址 (${want}) 不一致——助记词可能抄错，操作已中止`)
    }

    const result = await createWalletFromPrivateKey(passphrase, privateKey, email, false)
    return {
      ...result,
      note: '已从助记词重建分片体系（2-of-3）；⚠️ 请妥善保存新恢复码；旧恢复码/旧邮箱备份片仍可重组同一私钥——请作废销毁并删除旧邮件；原助记词仍可恢复（单点，建议销毁或严格保管）',
    }
  } finally {
    privateKey.fill(0) // 所有路径（成功/异常）均清零
  }
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
  try {
    vault.unlock([share1, share2])
    const sig = vault.signMessage(new TextEncoder().encode(message))
    const addr = vault.getAddress()
    return JSON.stringify({ address: addr, signature: Buffer.from(sig).toString('hex') })
  } finally {
    vault.wipe() // 异常路径也清零 vault 内组合私钥
    share1.bytes.fill(0)
    share2.bytes.fill(0)
  }
}

/** 恢复：输入任意 2 个恢复码 → 重组 → 新设备片（口令加密）+ 新恢复码（reshare）
 * 地址交叉校验（P1-1）：expectedAddress 或旧 metadata 地址不一致立即报错——
 * 防止输错恢复码静默恢复出「错误钱包」（新设备恢复场景必须传 expectedAddress）
 * 提供 email 时：自动将新片③发送到邮箱（更新旧邮箱备份；旧邮件中的分片仍有效，建议删除）
 * 原子性：所有可失败操作（含邮件/恢复码落盘）成功后才写 meta/device，失败整体回滚
 */
export async function restoreWallet(
  passphrase: string,
  recoveryCodes: [string, string],
  expectedAddress?: string,
  email?: string,
): Promise<InitResult> {
  validatePassphrase(passphrase)
  const shares = recoveryCodes.map(decodeRecoveryCode)
  const fresh = reshareShares(shares, { shares: 3, threshold: 2 })
  const enc = await encryptShare(fresh[0], passphrase)
  const privateKey = combineShares([fresh[0], fresh[1]])
  const { privateKeyToAddress } = await import('@wallet-service/core')
  const address = privateKeyToAddress(privateKey)

  // 地址交叉校验：期望地址 or 旧 metadata 地址
  const want = expectedAddress ?? (await readOldAddress())
  if (want && want.toLowerCase() !== address.toLowerCase()) {
    privateKey.fill(0)
    throw new Error(`恢复出的地址 (${address}) 与目标地址 (${want}) 不一致——恢复码可能输错，操作已中止`)
  }

  const newCodes = [fresh[1], fresh[2]].map(encodeRecoveryCode)

  // 可失败操作前置：邮箱备份（新片③）+ 恢复码落盘
  let backupStatus: 'sent' | 'skipped' | undefined
  if (email) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      privateKey.fill(0)
      throw new Error('邮箱格式无效')
    }
    backupStatus = await sendBackupShare(email, address, newCodes[1])
  }
  // 存储策略 A+B（同 createWalletFromPrivateKey）
  const emailed = backupStatus === 'sent'
  const localCodes = emailed ? [newCodes[0]] : newCodes
  const recoveryFileWritten = await saveRecoveryCodes(localCodes, emailed)

  // 原子落盘 + 回滚（失败时清理全部已写文件——含明文恢复码=私钥材料）
  try {
    await fs.mkdir(getHomeDir(), { recursive: true })
    await fs.writeFile(metaFile(), JSON.stringify({ version: 1, address }, null, 2), { mode: 0o600 })
    await fs.writeFile(deviceFile(), JSON.stringify({ version: 1, share: enc }, null, 2), { mode: 0o600 })
  } catch (err) {
    await fs.rm(metaFile(), { force: true })
    await fs.rm(deviceFile(), { force: true })
    await fs.rm(recoveryFileWritten, { force: true }) // 明文恢复码（2 片=私钥）
    throw err
  } finally {
    privateKey.fill(0)
  }

  return {
    address,
    recoveryCodes: newCodes,
    recoveryFile: recoveryFileWritten,
    backupEmail: email,
    backupStatus,
    note: email
      ? '新备份分片已发送到邮箱；请删除旧邮件中的备份分片（旧分片集仍可重组同一私钥）'
      : '如曾使用邮箱备份，请提供 email 重新备份（旧邮件中的分片仍有效，建议删除）',
  }
}

/** 从本地恢复码文件读取恢复码（MCP 场景：路径进 LLM，内容不进）
 * 注意：邮箱备份已送达时本地可能仅 1 片——调用方需自行判断是否足够
 */
export async function readRecoveryCodesFromFile(filePath?: string): Promise<string[]> {
  const file = filePath ?? path.join(getHomeDir(), 'recovery-codes.txt')
  const content = await fs.readFile(file, 'utf8')
  const codes = content.split('\n').filter((l) => l.trim().startsWith('sn1-')).map((l) => l.trim())
  if (codes.length === 0) throw new Error('恢复码文件为空')
  return codes
}

/** 导出 24 词助记词（模式 A：设备片 + 1 恢复码）——任意 2 片即可随时导出
 * ⚠️ 助记词=完整私钥（单点），导出前必须提示风险
 */
export async function exportMnemonic(passphrase: string, recoveryCode: string): Promise<{ mnemonicFile: string; address: string }> {
  const enc = JSON.parse(await fs.readFile(deviceFile(), 'utf8')) as { share: { data: string; salt: string } }
  const share1 = await decryptShare(enc.share, passphrase)
  const share2 = decodeRecoveryCode(recoveryCode)
  return exportMnemonicFromShares([share1, share2])
}

/** 导出 24 词助记词（模式 B：2 个恢复码，无设备场景） */
export async function exportMnemonicFromCodes(recoveryCode1: string, recoveryCode2: string): Promise<{ mnemonicFile: string; address: string }> {
  return exportMnemonicFromShares([decodeRecoveryCode(recoveryCode1), decodeRecoveryCode(recoveryCode2)])
}

/** 共享实现：组合私钥 → 助记词落盘；地址与本地 metadata 交叉校验防错组合 */
async function exportMnemonicFromShares(shares: Share[]): Promise<{ mnemonicFile: string; address: string }> {
  const { WalletVault } = await import('@wallet-service/signer')
  const vault = new WalletVault()
  let mnemonicFile: string
  let address: string
  try {
    vault.unlock(shares) // 私钥范围校验（0<priv<n），防静默坏组合
    address = vault.getAddress()
    const want = await readOldAddress()
    if (want && want.toLowerCase() !== address.toLowerCase()) {
      throw new Error(`组合出的地址 (${address}) 与本地钱包 (${want}) 不一致——恢复码可能输错，操作已中止`)
    }
    // 私钥已解锁但 WalletVault 不暴露私钥——用组合路径再拿一次（组合后立即清零）
    const privateKey = combineShares(shares)
    try {
      mnemonicFile = await saveMnemonic(privateKeyToMnemonic(privateKey))
    } finally {
      privateKey.fill(0)
    }
  } finally {
    vault.wipe()
    for (const s of shares) s.bytes.fill(0)
  }
  return { mnemonicFile, address }
}

/** 创建解锁令牌：本地口令+恢复码 → 组合私钥 → 短期单次解锁会话（P0-1） */
export async function createUnlockToken(passphrase: string, recoveryCode: string): Promise<string> {
  const enc = JSON.parse(await fs.readFile(deviceFile(), 'utf8')) as { share: { data: string; salt: string } }
  const share1 = await decryptShare(enc.share, passphrase)
  const share2 = decodeRecoveryCode(recoveryCode)
  let privateKey: Uint8Array | null = null
  try {
    privateKey = combineShares([share1, share2])
    // 地址交叉校验：防止输错恢复码生成「垃圾私钥」令牌（签名被拒且用户不知原因）
    const { privateKeyToAddress } = await import('@wallet-service/core')
    const want = await readOldAddress()
    if (want && privateKeyToAddress(privateKey).toLowerCase() !== want.toLowerCase()) {
      throw new Error('组合出的地址与本地钱包不一致——恢复码可能输错，操作已中止')
    }
    return await createUnlockSession(privateKey)
  } finally {
    privateKey?.fill(0) // 异常路径也清零
    share1.bytes.fill(0)
    share2.bytes.fill(0)
  }
}

/** 确认短语：彻底删除必须输入的不可逆确认 */
export const WIPE_CONFIRM_PHRASE = 'PERMANENT DELETE'

/**
 * 安全删除单个文件：随机数据覆写 3 遍（尽力抹除，防常规恢复）→ unlink。
 * SSD 闪存级残余需取证设备才能读取，普通威胁模型下不可恢复。
 */
async function secureDelete(file: string): Promise<void> {
  let overwritten = false
  try {
    const stat = await fs.stat(file)
    if (stat.size > 0) {
      const fh = await fs.open(file, 'r+')
      try {
        for (let pass = 0; pass < 3; pass++) {
          let written = 0
          while (written < stat.size) {
            // 每个位置生成新随机块（防模式可预测）+ 分块防大文件内存
            const chunk = randomBytes(Math.min(64 * 1024, stat.size - written))
            const n = await fh.write(chunk, 0, chunk.length, written)
            written += typeof n === 'number' ? n : n.bytesWritten
          }
        }
        await fh.sync().catch(() => {})
        overwritten = true
      } finally {
        await fh.close().catch(() => {}) // 保证句柄释放
      }
    }
  } catch (err) {
    // 覆写失败不静默——提示后仍删除（调用方知情，避免虚假的'安全删除'印象）
    console.warn(`覆写失败 ${file}: ${(err as Error).message}，仅执行普通删除`)
  }
  await fs.rm(file, { force: true })
  void overwritten
}

/** wipe 范围：all=本机全部密钥材料 / saved=仅'需用户保存'的明文备份（恢复码+助记词） */
export type WipeScope = 'all' | 'saved'

/** 恢复码本地存储状态（按 recovery-codes.txt 实况判断，供交互引导） */
export type RecoveryFileStatus = 'emailed' | 'local-only' | 'missing'

/** 检测恢复码存储状态：1 片=邮箱已送达（片③在邮箱）/ 2 片=本地集中 / 无文件 */
export async function getRecoveryFileStatus(): Promise<RecoveryFileStatus> {
  try {
    const content = await fs.readFile(recoveryFile(), 'utf8')
    const count = content.split('\n').filter((l) => l.trim().startsWith('sn1-')).length
    if (count >= 2) return 'local-only'
    if (count === 1) return 'emailed'
    return 'missing'
  } catch {
    return 'missing'
  }
}

/** 列出当前存在的'需用户保存'文件（basename，供展示确认） */
export async function listSavedFiles(): Promise<string[]> {
  const names: string[] = []
  for (const f of [recoveryFile(), mnemonicFile()]) {
    try {
      await fs.stat(f)
      names.push(path.basename(f))
    } catch {
      // 不存在跳过
    }
  }
  return names
}

/**
 * 彻底删除（不可恢复，覆写 3 遍 + unlink）：
 * - scope='saved'：仅删'需用户保存'的明文备份（recovery-codes.txt / mnemonic.txt）——
 *   本机不再有可被窃取的明文恢复码/助记词；钱包本体（设备片）保留，口令解锁继续可用
 * - scope='all'：删除本机全部密钥材料（device-share / recovery / mnemonic / metadata / unlock 会话）
 * - 执行前必须输入确认短语 WIPE_CONFIRM_PHRASE（防误删）
 * - ⚠️ 调用前必须提醒用户：确认已保存恢复码/助记词（用户保存的那一份是唯一恢复途径）
 * @returns removed 为 basename 清单（展示用）
 */
export async function wipeWallet(confirmPhrase: string, scope: WipeScope = 'all'): Promise<{ removed: string[] }> {
  if (confirmPhrase !== WIPE_CONFIRM_PHRASE) {
    throw new Error('确认短语不匹配，已中止（防止误删）')
  }
  const removed: string[] = []
  const targets = scope === 'saved'
    ? [recoveryFile(), mnemonicFile()]
    : [metaFile(), deviceFile(), recoveryFile(), mnemonicFile()]
  for (const f of targets) {
    try {
      await fs.stat(f)
      await secureDelete(f)
      removed.push(path.basename(f))
    } catch {
      // 不存在则跳过
    }
  }
  if (scope === 'all') {
    // unlock/ 目录（令牌会话）
    try {
      const dir = getUnlockDir()
      const entries = await fs.readdir(dir)
      for (const e of entries) {
        const f = path.join(dir, e)
        await secureDelete(f)
        removed.push(path.basename(f))
      }
      await fs.rmdir(dir).catch(() => {})
    } catch {
      // 无 unlock 目录
    }
  }
  return { removed }
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
