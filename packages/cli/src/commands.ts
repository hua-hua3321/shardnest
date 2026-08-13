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
  kdfParamsOf,
  LEGACY_SCRYPT_OPTS_V1,
  type KdfParams,
  type Share,
} from '@wallet-services/core'
import { gcm } from '@noble/ciphers/aes'
import { sendBackupShare } from './mailer'
import { createUnlockSession, getUnlockDir } from '@wallet-services/signer'
import { randomBytes } from '@noble/hashes/utils'
import { randomUUID } from 'node:crypto'
import { entropyToMnemonic, mnemonicToEntropy, generateEntropy } from '@wallet-services/core'

/** 钱包目录（动态读取 env，便于测试隔离） */
export function getHomeDir(): string {
  // I19: 空串/空白 SHARDNEST_HOME 也回退默认（?? 只对 null/undefined 生效，
  // 显式设空会导致钱包落到当前工作目录）
  const home = process.env.SHARDNEST_HOME?.trim()
  return home && home.length > 0 ? home : path.join(process.env.HOME ?? '.', '.shardnest')
}
const metaFile = () => path.join(getHomeDir(), 'metadata.json')
const deviceFile = () => path.join(getHomeDir(), 'device-share.json')
const recoveryFile = () => path.join(getHomeDir(), 'recovery-codes.txt')
const mnemonicFile = () => path.join(getHomeDir(), 'mnemonic.txt')

/**
 * 原子写文件（P0-2 基础）：staging（同目录 .tmp-<rand>，O_EXCL 防符号链接跟随）
 * → fsync → rename 替换。失败时旧文件零接触（staging 清理后即无痕）。
 * rename 后显式 chmod（中风险: 已有宽松权限文件被 rename 替换后仍保持旧权限）
 * @returns 正式文件路径
 */
async function writeFileAtomic(file: string, content: string, mode: number): Promise<string> {
  await fs.mkdir(path.dirname(file), { recursive: true })
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}.tmp-${randomUUID()}`)
  let fh: Awaited<ReturnType<typeof fs.open>>
  try {
    fh = await fs.open(tmp, 'wx', mode) // O_CREAT|O_EXCL
    try {
      await fh.writeFile(content)
      await fh.sync() // 数据落盘后才 rename（崩溃一致性）
    } finally {
      await fh.close().catch(() => {})
    }
  } catch (err) {
    // 写入/sync 失败：staging 可能已含明文——安全删除而非普通 rm（防明文残留）
    await secureDelete(tmp).catch(() => {})
    throw err
  }
  await fs.rename(tmp, file)
  await fs.chmod(file, mode).catch(() => {}) // 防已有文件保留宽松权限
  return file
}

/**
 * 多文件事务式提交（P0-2 + 整组原子性修复）：
 * 1. 全部写入 staging + fsync（任一失败 → 清理 staging，正式路径零接触）
 * 2. 已存在的目标文件先 rename 到 .bak-<uuid>（备份；单个 rename 原子）
 * 3. 逐个 rename staging → 正式（任一失败 → 回滚：备份恢复覆盖新文件 + 删除无备份的新文件）
 *
 * 之前实现只保证单文件原子：rename 中途失败会留下「新 metadata/device + 旧 recovery」
 * 的混合钱包。备份使 rename 阶段失败可可靠回滚到旧状态。
 */
async function commitAtomically(files: { file: string; content: string; mode: number }[]): Promise<void> {
  // 启动前清理历史 staging（上次异常中断残留的 .tmp-*，可能含明文恢复码/助记词）
  await cleanupStaleStaging()
  const tmps: { tmp: string; final: string }[] = []
  const backups: { bak: string; final: string }[] = [] // 已存在目标文件的备份（rename 前收集）
  let renamed = 0 // 已成功切换的 staging 数（回滚依据）
  try {
    for (const f of files) {
      await fs.mkdir(path.dirname(f.file), { recursive: true })
      // 中风险: 钱包目录收紧 0700（默认 umask 可能留 0755）
      await fs.chmod(path.dirname(f.file), 0o700).catch(() => {})
      const tmp = path.join(path.dirname(f.file), `.${path.basename(f.file)}.tmp-${randomUUID()}`)
      // ⚠️ open 前立即登记——写入/sync/close 失败时也必须被清理（防明文 staging 残留）
      tmps.push({ tmp, final: f.file })
      let fh: Awaited<ReturnType<typeof fs.open>>
      try {
        fh = await fs.open(tmp, 'wx', f.mode)
        try {
          await fh.writeFile(f.content)
          await fh.sync()
        } finally {
          await fh.close().catch(() => {})
        }
      } catch (err) {
        // 该 staging 可能已含明文（恢复码/助记词）——安全删除而非普通 rm
        await secureDelete(tmp).catch(() => {})
        throw err
      }
    }
    // 备份已存在的目标文件（rename 原子；备份失败前目标未被触碰）
    for (const t of tmps) {
      try {
        await fs.stat(t.final)
      } catch {
        continue // 目标不存在，无需备份
      }
      const bak = `${t.final}.bak-${randomUUID()}`
      await fs.rename(t.final, bak)
      backups.push({ bak, final: t.final })
    }
    // 逐个切换（rename 原子；失败进入回滚）
    for (const t of tmps) {
      await fs.rename(t.tmp, t.final)
      await fs.chmod(t.final, files.find((f) => f.file === t.final)!.mode).catch(() => {}) // 防已有宽松权限
      renamed++
    }
  } catch (err) {
    // 回滚：备份恢复（rename 覆盖新文件，原子恢复旧版本）
    for (const b of backups) {
      await fs.rename(b.bak, b.final).catch(() => {})
    }
    // 删除已切换但原本不存在的文件（无备份可恢复）
    const restored = new Set(backups.map((b) => b.final))
    for (let i = 0; i < renamed; i++) {
      if (!restored.has(tmps[i].final)) await fs.rm(tmps[i].final, { force: true }).catch(() => {})
    }
    // 清理所有残留 staging（可能含明文——安全删除）
    for (const t of tmps) await secureDelete(t.tmp).catch(() => {})
    throw err
  }
  // 成功路径：安全删除旧备份（覆写 3 遍——旧材料含明文恢复码/助记词，禁止普通 rm）。
  // 事务已提交，此处失败不回滚（会破坏新状态），而是抛错提示残留路径供用户处理
  for (const b of backups) {
    try {
      await secureDelete(b.bak)
    } catch (err) {
      throw new Error(`钱包已更新，但旧材料备份 ${path.basename(b.bak)} 删除失败，请手动安全删除（覆写后移除）：${(err as Error).message}`)
    }
  }
}

/** 助记词内容构造（与落盘分离，供事务式提交） */
export function buildMnemonicContent(mnemonic: string): string {
  return [
    '# shardnest 24 词助记词备份（完整私钥，单点！请勿拍照/截图/网络传输）',
    '# 单凭此 24 词即可恢复钱包；泄露即资金丢失（与分片恢复码不同，无门限保护）',
    '',
    mnemonic,
    '',
  ].join('\n') + '\n'
}

/** 助记词落盘（0600；助记词=完整私钥，用户选择生成即接受单点保管；原子替换） */
export async function saveMnemonic(mnemonic: string): Promise<string> {
  return writeFileAtomic(mnemonicFile(), buildMnemonicContent(mnemonic), 0o600)
}

/** 恢复码内容构造（与落盘分离，供事务式提交） */
export function buildRecoveryCodesContent(codes: string[], emailed = false): string {
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
  return [...header, '', ...codes.map((c) => c + '')].join('\n') + '\n'
}

/** 恢复码落盘（0600 明文，用户自持责任；与纸备份等价，供 MCP 场景免 LLM 交付）
 * 存储策略（方案 A+B）：
 * - 邮箱发送成功（1 片本地）→ 本地仅存 1 片，头部说明另一片在邮箱——本机整体失守无法动钱
 * - 未发邮箱（2 片本地）→ 显著警告：本地集中 2 片=私钥，整体泄露即失守，建议转移/配邮箱
 */
export async function saveRecoveryCodes(codes: string[], emailed = false): Promise<string> {
  return writeFileAtomic(recoveryFile(), buildRecoveryCodesContent(codes, emailed), 0o600)
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

/**
 * 恢复码编码（P1-2 批次绑定）：
 * - sn2-<setid>-<index>-<hex>-<crc>（新，带 8 字节随机批次 ID）
 * - sn1-<index>-<hex>-<crc>（旧，无批次——decode 时 setId 为 undefined）
 * CRC = keccak256 前 4 字节，覆盖 setid:index:hex——同批分片必须 setId 一致，
 * 杜绝「混用两套不同钱包的恢复码静默恢复出第三方钱包」
 * @param setId 批次 ID（init/restore 时生成一次，同批 3 片共享）；省略则编码 sn1
 */
export function encodeRecoveryCode(share: Share, setId?: string): string {
  const hex = Buffer.from(share.bytes).toString('hex')
  const idPart = setId ?? ''
  const crc = Buffer.from(keccak_256(new TextEncoder().encode(`${idPart}${share.index}:${hex}`)).slice(0, 4)).toString('hex')
  return setId ? `sn2-${setId}-${share.index}-${hex}-${crc}` : `sn1-${share.index}-${hex}-${crc}`
}

export function decodeRecoveryCode(code: string): Share {
  const parts = code.trim().split('-')
  // sn2-<setid>-<index>-<hex>-<crc>（5 段）或 sn1-<index>-<hex>-<crc>（4 段）
  if (parts.length === 5 && parts[0] === 'sn2') {
    const [, setId, idx, hex, crc] = parts
    if (!/^[0-9a-f]{16}$/.test(setId)) throw new Error('恢复码批次 ID 格式无效')
    const index = Number(idx)
    if (!Number.isInteger(index) || index < 1 || index > 255) throw new Error('恢复码 index 超出有效范围')
    if (!/^[0-9a-f]{2,128}$/.test(hex) || hex.length % 2 !== 0) throw new Error('恢复码 hex 格式无效')
    const expectCrc = Buffer.from(keccak_256(new TextEncoder().encode(`${setId}${index}:${hex}`)).slice(0, 4)).toString('hex')
    if (crc !== expectCrc) throw new Error('恢复码校验失败（可能抄错/损坏），请核对后重试')
    return { index, bytes: new Uint8Array(Buffer.from(hex, 'hex')), setId }
  }
  if (parts.length === 4 && parts[0] === 'sn1') {
    const [, idx, hex, crc] = parts
    const index = Number(idx)
    // index 必须为 [1,255] 整数（GF(256) x 坐标域）
    if (!Number.isInteger(index) || index < 1 || index > 255) throw new Error('恢复码 index 超出有效范围')
    if (!/^[0-9a-f]{2,128}$/.test(hex) || hex.length % 2 !== 0) throw new Error('恢复码 hex 格式无效')
    // O3: 32 位 CRC；W4 双宽兼容——旧 8 位码（批次前生成）仍放行（恢复码无法重新获取）
    const k = keccak_256(new TextEncoder().encode(`${index}:${hex}`))
    const crc32 = Buffer.from(k.slice(0, 4)).toString('hex')
    const crc8 = k[0].toString(16).padStart(2, '0')
    if (crc !== crc32 && crc !== crc8) throw new Error('恢复码校验失败（可能抄错/损坏），请核对后重试')
    return { index, bytes: new Uint8Array(Buffer.from(hex, 'hex')) }
  }
  throw new Error('无效恢复码格式')
}

/**
 * P1-2: 校验一组分片属于同一批次。
 * 严格二选一（防 sn2+sn1 混用绕过批次校验）：
 * - 含 sn2（带 setId）：全部必须带 setId 且一致——sn1/sn2 混合一律拒绝
 * - 全 sn1（无 setId）：无法校验批次，依赖地址交叉校验兜底
 */
function assertSameShareSet(shares: Share[]): void {
  const withIds = shares.filter((s) => s.setId !== undefined)
  const withoutIds = shares.filter((s) => s.setId === undefined)
  if (withIds.length > 0 && withoutIds.length > 0) {
    throw new Error('恢复码新旧格式混用（sn2 与 sn1）——无法确认同一批次，操作已中止')
  }
  if (withIds.length > 0) {
    const setIds = new Set(withIds.map((s) => s.setId as string))
    if (setIds.size > 1) {
      throw new Error('恢复码来自不同批次（可能混用了两个钱包的恢复码），操作已中止')
    }
  }
}

/** 加密设备分片（O1：KDF 参数随密文持久化——未来 scrypt 升级不破坏旧钱包） */
async function encryptShare(share: Share, passphrase: string): Promise<{ data: string; salt: string; kdf?: KdfParams }> {
  const salt = randomBytes(16)
  const kdf = kdfParamsOf() // 当前常量参数，持久化供解密
  const kek = await deriveKEK(passphrase, salt, kdf)
  try {
    const nonce = randomBytes(12)
    const cipher = gcm(kek, nonce)
    const payload = new Uint8Array(1 + share.bytes.length)
    payload[0] = share.index
    payload.set(share.bytes, 1)
    const ct = cipher.encrypt(payload)
    return {
      data: Buffer.from(nonce).toString('base64') + '.' + Buffer.from(ct).toString('base64'),
      salt: Buffer.from(salt).toString('base64'),
      kdf, // O1: KDF 参数随密文持久化
    }
  } finally {
    kek.fill(0) // 中风险: KEK 用后清零（不变式 5 精神）
  }
}

/** 解密设备分片（v1 无 kdf 字段 → 用默认参数，兼容旧钱包） */
/** 解密设备分片：v2+ 用密文持久化 kdf 参数；v1（无 kdf 字段）回退历史 2^16 参数
 * （C1：回退必须用 v1 实际加密参数，否则真实 v1 钱包被锁出） */
async function decryptShare(enc: { data: string; salt: string; kdf?: KdfParams }, passphrase: string): Promise<Share> {
  const salt = Uint8Array.from(Buffer.from(enc.salt, 'base64'))
  const kek = await deriveKEK(passphrase, salt, enc.kdf ?? LEGACY_SCRYPT_OPTS_V1)
  try {
    const [nonceB64, ctB64] = enc.data.split('.')
    const nonce = Uint8Array.from(Buffer.from(nonceB64, 'base64'))
    const ct = Uint8Array.from(Buffer.from(ctB64, 'base64'))
    const cipher = gcm(kek, nonce)
    let payload: Uint8Array
    try {
      payload = cipher.decrypt(ct)
    } catch {
      // I10: AES-GCM 认证失败 = 口令错误或分片损坏——给用户可操作的提示而非库原始错误
      throw new Error('口令错误，或设备分片已损坏——请核对口令后重试')
    }
    return { index: payload[0], bytes: payload.slice(1) }
  } finally {
    kek.fill(0) // 中风险: KEK 用后清零（不变式 5 精神）
  }
}

/** 香农熵估算（bits）：基于口令字符的经验频率分布，重复字符越多熵越低。
 * 用于补强"字符类"检查的盲区——如 `Aaaaaaaaaaaa1` 含 2 类却熵极低。 */
function estimatePassphraseEntropy(s: string): number {
  const freq = new Map<string, number>()
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1)
  const n = s.length
  let h = 0
  for (const c of freq.values()) {
    const p = c / n
    h -= p * Math.log2(p)
  }
  return h * n
}

/** 口令强度校验（≥12 位 + 至少 2 种字符类 + 反模式检测 + 熵下限，防弱口令爆破设备分片） */
export function validatePassphrase(passphrase: string): void {
  if (passphrase.length < 12) {
    throw new Error('口令至少 12 位（建议混合大小写/数字/符号）')
  }
  // 字符类计数（小写/大写/数字/符号）
  let classes = 0
  if (/[a-z]/.test(passphrase)) classes++
  if (/[A-Z]/.test(passphrase)) classes++
  if (/[0-9]/.test(passphrase)) classes++
  if (/[^a-zA-Z0-9]/.test(passphrase)) classes++
  if (classes < 2) {
    throw new Error('口令至少包含 2 种字符类型（小写/大写/数字/符号）')
  }
  // 反模式检测：全相同字符
  if (/^(.)\1+$/.test(passphrase)) {
    throw new Error('口令不能为重复字符')
  }
  // 反模式检测：连续键盘序列（qwerty/asdf/1234/abcd 等 ≥4 位）
  const sequences = [
    'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
    '1234567890', 'abcdefghijklmnopqrstuvwxyz',
  ]
  const lower = passphrase.toLowerCase()
  for (const seq of sequences) {
    for (let i = 0; i <= seq.length - 4; i++) {
      const sub = seq.slice(i, i + 4)
      if (lower.includes(sub) || lower.includes(sub.split('').reverse().join(''))) {
        throw new Error('口令不能包含连续键盘或字母序列（≥4 位）')
      }
    }
  }
  // P1-4：熵下限（防低熵口令绕过"字符类"检查，如 Aaaaaaaaaaaa1）。
  // 香农熵估算——重复字符越多熵越低，可捕获"表面多类、实质弱"的口令。
  const entropy = estimatePassphraseEntropy(passphrase)
  if (entropy < 30) {
    throw new Error('口令熵过低（疑似弱口令），请使用更长或更随机的口令')
  }
}

/** 平台背书密钥对（第三方平台接入 shardnest 用，init-platform 命令）：
 * 平台自持私钥仅用于签发 signed_request；地址公开，配置到钱包服务白名单。
 * 本函数只生成 + 返回（hex），不落盘——私钥安全由平台自行负责（KMS/HSM/安全存储）。
 */
export function generatePlatformKeypair(): { address: string; privateKeyHex: string } {
  const kp = generateKeyPair()
  return {
    address: kp.address,
    privateKeyHex: Buffer.from(kp.privateKey).toString('hex'),
  }
}

/** 初始化：生成密钥对 → 2-of-3 分片 → 片①口令加密存设备 → 返回恢复码②③
 * 提供 email 时：自动将片③（备份分片）发送到邮箱（SMTP 未配置则 skipped）
 * mnemonic=true 时：同步生成 24 词助记词（完整私钥备份，可单独恢复；默认关闭）
 * 原子性：先完成所有可失败操作（邮件/恢复码/助记词落盘）→ 最后落盘，失败不留下半成品
 */
export async function initWallet(passphrase: string, email?: string, mnemonic = false, force = false): Promise<InitResult> {
  validatePassphrase(passphrase)
  // W9: 防静默覆盖——已有钱包时默认拒绝（旧钱包未备份恢复码即永久丢失）
  const existing = await readOldAddress()
  if (existing !== undefined && !force) {
    throw new Error(
      `钱包已存在（地址 ${existing}）。如需重新创建请先执行 wipe，或用 restore 恢复；强制覆盖需传 force=true（旧钱包若未备份恢复码，资金将永久丢失）`
    )
  }
  const entropy = generateEntropy() // O4A: 钱包根=熵（分片对象；私钥为派生）
  return createWalletFromEntropy(passphrase, entropy, email, mnemonic)
}

/** 从既定熵建钱包（init/恢复码恢复/助记词恢复共用；调用方负责 entropy 清零）
 * O4A: 分片对象=熵（32 字节）——任意 2 片可导出助记词，也可派生私钥签名
 * W3: 敏感材料创建后立即进入 try/finally——所有早抛路径（邮箱校验/落盘失败）
 *     均保证熵/私钥/分片清零（不变式 5） */
async function createWalletFromEntropy(
  passphrase: string,
  entropy: Uint8Array,
  email?: string,
  mnemonic = false,
): Promise<InitResult> {
  const { privateKeyToAddress, derivePrivateKeyFromEntropy } = await import('@wallet-services/core')
  const privateKey = derivePrivateKeyFromEntropy(entropy) // BIP-39/44 派生
  const address = privateKeyToAddress(privateKey)
  const shares = splitSecret(entropy, { shares: 3, threshold: 2 })
  try {
    const enc = await encryptShare(shares[0], passphrase)
    // P1-2: 本批次恢复码共享同一随机 setId（8 字节）——混用跨钱包分片即被批次校验拒绝
    const setId = Buffer.from(randomBytes(8)).toString('hex')
    const recoveryCodes = [shares[1], shares[2]].map((s) => encodeRecoveryCode(s, setId))

    // 1. 可失败操作先行：邮箱校验 + 发送（失败抛错 → 不落盘）
    let backupStatus: 'sent' | 'skipped' | undefined
    if (email) {
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        throw new Error('邮箱格式无效')
      }
      backupStatus = await sendBackupShare(email, address, recoveryCodes[1])
    }

    // 2. 可失败操作全部前置（邮箱/助记词内容构造，不落盘）
    //    存储策略 A+B：邮箱已送达（sent）→ 本地只存片②（片③在邮箱，三处分布）；
    //    skipped/无邮箱 → 本地存 2 片（显著警告，用户自担）
    const emailed = backupStatus === 'sent'
    const localCodes = emailed ? [recoveryCodes[0]] : recoveryCodes

    // 3. 事务式提交（P0-2）：meta/device/recovery/mnemonic 全部先写 staging +
    //    fsync，全部成功后才逐个 rename。任一失败 → 清理 staging，正式路径
    //    零接触——force 覆盖旧钱包时失败，旧钱包完整保留（不再删旧文件）
    const files: { file: string; content: string; mode: number }[] = [
      { file: metaFile(), content: JSON.stringify({ version: 1, address }, null, 2), mode: 0o600 },
      { file: deviceFile(), content: JSON.stringify({ version: 2, share: enc }, null, 2), mode: 0o600 },
      { file: recoveryFile(), content: buildRecoveryCodesContent(localCodes, emailed), mode: 0o600 },
    ]
    if (mnemonic) {
      files.push({ file: mnemonicFile(), content: buildMnemonicContent(entropyToMnemonic(entropy)), mode: 0o600 })
    }
    await commitAtomically(files)

    return {
      address,
      recoveryCodes,
      backupEmail: email,
      backupStatus,
      recoveryFile: recoveryFile(),
      mnemonicFile: mnemonic ? mnemonicFile() : undefined,
      note: mnemonic
        ? '助记词已生成（=完整私钥，单点）：请抄写并安全保管，勿拍照/截图/网络传输；建议抄写离线保存后执行 wipe 删除本机明文备份'
        : undefined,
    }
  } finally {
    privateKey.fill(0) // 派生私钥清零
    entropy.fill(0) // O4A: 根熵清零（=私钥材料）
    for (const s of shares) s.bytes.fill(0) // 不变式 5：明文分片一并清零（任意 2 片=熵）
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
  const entropy = mnemonicToEntropy(mnemonic) // O4A: 标准 24 词 → 熵（校验和校验）
  try {
    const { privateKeyToAddress, derivePrivateKeyFromEntropy } = await import('@wallet-services/core')
    const address = privateKeyToAddress(derivePrivateKeyFromEntropy(entropy))

    const want = expectedAddress ?? (await readOldAddress())
    if (want && want.toLowerCase() !== address.toLowerCase()) {
      throw new Error(`助记词恢复出的地址 (${address}) 与目标地址 (${want}) 不一致——助记词可能抄错，操作已中止`)
    }

    const result = await createWalletFromEntropy(passphrase, entropy, email, false)
    return {
      ...result,
      note: '已从助记词重建分片体系（2-of-3）；⚠️ 请妥善保存新恢复码；旧恢复码/旧邮箱备份片仍可重组同一私钥——请作废销毁并删除旧邮件；原助记词仍可恢复（单点，建议销毁或严格保管）。注意：本版本起助记词为标准 BIP-39/44 语义（熵→m/44\'/60\'/0\'/0/0 派生）——旧版本生成的助记词（私钥直接编码）在新版本下无法恢复同一地址，请用旧版本软件或恢复码恢复',
    }
  } finally {
    entropy.fill(0) // O4A: 根熵清零（所有路径）
  }
}

/** 显示地址（无需口令） */
export async function getAddress(): Promise<string> {
  const meta = JSON.parse(await fs.readFile(metaFile(), 'utf8')) as { address?: string }
  const addr = meta.address
  // I18: metadata 被篡改成有效 JSON 但无合法地址时——干净拒绝而非裸 TypeError
  if (typeof addr !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(addr)) {
    throw new Error('metadata 损坏或缺少合法地址——请检查设备文件后重试')
  }
  return addr
}

/** 解锁并签名：口令解锁设备片① + 用户提供 1 个恢复码 → EIP-191 签名 */
export async function signMessage(passphrase: string, recoveryCode: string, message: string): Promise<string> {
  const enc = JSON.parse(await fs.readFile(deviceFile(), 'utf8')) as { share: { data: string; salt: string } }
  const share1 = await decryptShare(enc.share, passphrase)
  const share2 = decodeRecoveryCode(recoveryCode)
  const { WalletVault } = await import('@wallet-services/signer')
  const { privateKeyToAddress, derivePrivateKeyFromEntropy } = await import('@wallet-services/core')
  const vault = new WalletVault()
  const entropy = combineShares([share1, share2]) // O4A: 重组根熵
  let privateKey: Uint8Array | null = null
  try {
    privateKey = derivePrivateKeyFromEntropy(entropy) // BIP-39/44 派生
    // P1-1: 地址交叉校验——恢复码与设备片不匹配时拒绝（防签出另一地址的签名被平台拒）
    const want = await readOldAddress()
    if (want && privateKeyToAddress(privateKey).toLowerCase() !== want.toLowerCase()) {
      throw new Error('组合出的地址与本地钱包不一致——恢复码可能输错，操作已中止')
    }
    vault.unlockPrivateKey(privateKey) // O4A: 组合/派生已在命令层完成
    const sig = vault.signMessage(new TextEncoder().encode(message))
    const addr = vault.getAddress()
    return JSON.stringify({ address: addr, signature: Buffer.from(sig).toString('hex') })
  } finally {
    vault.wipe() // 异常路径也清零 vault 内组合私钥
    privateKey?.fill(0)
    entropy.fill(0) // 根熵清零
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
  assertSameShareSet(shares) // P1-2: 混用两个钱包的恢复码 → 批次不一致 → 拒绝
  // P1（全仓审计）：全 sn1（legacy，无批次标识）时，若无本地可信 metadata 且未传
  // expectedAddress——无法确认两片来自同一钱包，新设备混用会静默恢复出「第三个钱包」，拒绝
  const isLegacyOnly = shares.every((s) => s.setId === undefined)
  if (isLegacyOnly) {
    const want = expectedAddress ?? (await readOldAddress())
    if (!want) {
      throw new Error('旧版恢复码（sn1）缺少批次标识，无法自动确认来自同一钱包；新设备恢复必须提供期望地址（expectedAddress）')
    }
  }
  const fresh = reshareShares(shares, { shares: 3, threshold: 2 })
  const enc = await encryptShare(fresh[0], passphrase)
  const entropy = combineShares([fresh[0], fresh[1]]) // O4A: 重组根熵
  const { privateKeyToAddress, derivePrivateKeyFromEntropy } = await import('@wallet-services/core')
  const privateKey = derivePrivateKeyFromEntropy(entropy) // BIP-39/44 派生
  const address = privateKeyToAddress(privateKey)

  // 地址交叉校验：期望地址 or 旧 metadata 地址
  const want = expectedAddress ?? (await readOldAddress())
  if (want && want.toLowerCase() !== address.toLowerCase()) {
    privateKey.fill(0)
    entropy.fill(0)
    throw new Error(`恢复出的地址 (${address}) 与目标地址 (${want}) 不一致——恢复码可能输错，操作已中止`)
  }

  // P1-2: 新恢复码使用新批次 ID（reshare 后旧批次作废，靠物理清理旧载体）
  const newSetId = Buffer.from(randomBytes(8)).toString('hex')
  const newCodes = [fresh[1], fresh[2]].map((s) => encodeRecoveryCode(s, newSetId))

  // 可失败操作前置：邮箱备份（新片③）+ 恢复码落盘
  let backupStatus: 'sent' | 'skipped' | undefined
  if (email) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      privateKey.fill(0)
      entropy.fill(0)
      throw new Error('邮箱格式无效')
    }
    backupStatus = await sendBackupShare(email, address, newCodes[1])
  }
  // 存储策略 A+B（同 createWalletFromPrivateKey）
  const emailed = backupStatus === 'sent'
  const localCodes = emailed ? [newCodes[0]] : newCodes

  // 事务式提交（P0-2）：meta/device/recovery 全部 staging + fsync 成功后统一
  // rename。任一失败 → 清理 staging，正式路径零接触——恢复失败时旧钱包完整保留
  try {
    await commitAtomically([
      { file: metaFile(), content: JSON.stringify({ version: 1, address }, null, 2), mode: 0o600 },
      { file: deviceFile(), content: JSON.stringify({ version: 2, share: enc }, null, 2), mode: 0o600 },
      { file: recoveryFile(), content: buildRecoveryCodesContent(localCodes, emailed), mode: 0o600 },
    ])
  } finally {
    privateKey.fill(0)
    entropy.fill(0) // O4A: 根熵清零
    for (const s of [...shares, ...fresh]) s.bytes.fill(0) // 不变式 5：输入 2 片 + 新 3 片一并清零
  }

  return {
    address,
    recoveryCodes: newCodes,
    recoveryFile: recoveryFile(),
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
  // P1-2: 同时识别 sn1/sn2 前缀（sn2 携带批次 ID）
  const codes = content.split('\n').filter((l) => /^(sn1|sn2)-/.test(l.trim())).map((l) => l.trim())
  if (codes.length === 0) throw new Error('恢复码文件为空')
  return codes
}

/** 方案 A：自动从恢复码文件读取第一片（CLI unlock/sign 免手输恢复码）。
 * 回退语义（P3）：仅「文件不存在（ENOENT）」与「无合法恢复码」视为可回退 → 返回 null；
 * 其余错误（权限/路径是目录/I/O）直接抛出——静默吞错会掩盖配置/权限故障。
 * 显式 --recovery-file 路径的任意读取错误一律直抛（用户明确指定了文件，必须知道结果）。
 * 安全语义：与手动输入该文件内容在威胁模型上等价（同用户权限恶意软件均可读），
 * 不改变双因素分离引导（emailed 状态提示仍保留）。 */
export async function tryReadRecoveryCodeFromFile(filePath?: string): Promise<string | null> {
  try {
    const codes = await readRecoveryCodesFromFile(filePath)
    return codes[0] ?? null
  } catch (err) {
    if (filePath) throw err // 显式指定文件：任何错误都报告，不静默回退
    const code = (err as NodeJS.ErrnoException).code
    if (code === 'ENOENT') return null // 默认文件不存在 → 回退手动输入
    if (err instanceof Error && err.message === '恢复码文件为空') return null // 空文件 → 回退手动输入
    throw err // 权限错误/路径是目录/其他 I/O 错误 → 暴露给用户（配置问题应被看见）
  }
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
  const s1 = decodeRecoveryCode(recoveryCode1)
  const s2 = decodeRecoveryCode(recoveryCode2)
  assertSameShareSet([s1, s2]) // P1-2: 混用两个钱包的恢复码 → 批次不一致 → 拒绝
  return exportMnemonicFromShares([s1, s2])
}

/** 共享实现：组合根熵 → 助记词落盘；地址与本地 metadata 交叉校验防错组合 */
async function exportMnemonicFromShares(shares: Share[]): Promise<{ mnemonicFile: string; address: string }> {
  const { privateKeyToAddress, derivePrivateKeyFromEntropy } = await import('@wallet-services/core')
  const entropy = combineShares(shares) // O4A: 重组根熵
  let mnemonicFile: string
  let address: string
  try {
    const privateKey = derivePrivateKeyFromEntropy(entropy) // BIP-39/44 派生
    try {
      address = privateKeyToAddress(privateKey)
      const want = await readOldAddress()
      if (want && want.toLowerCase() !== address.toLowerCase()) {
        throw new Error(`组合出的地址 (${address}) 与本地钱包 (${want}) 不一致——恢复码可能输错，操作已中止`)
      }
      mnemonicFile = await saveMnemonic(entropyToMnemonic(entropy)) // 熵↔助记词可逆，任意 2 片随时导出
    } finally {
      privateKey.fill(0)
    }
  } finally {
    entropy.fill(0)
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
  const entropy = combineShares([share1, share2]) // O4A: 重组根熵
  try {
    const { privateKeyToAddress, derivePrivateKeyFromEntropy } = await import('@wallet-services/core')
    privateKey = derivePrivateKeyFromEntropy(entropy) // BIP-39/44 派生
    // 地址交叉校验：防止输错恢复码生成「垃圾私钥」令牌（签名被拒且用户不知原因）
    const want = await readOldAddress()
    if (want && privateKeyToAddress(privateKey).toLowerCase() !== want.toLowerCase()) {
      throw new Error('组合出的地址与本地钱包不一致——恢复码可能输错，操作已中止')
    }
    return await createUnlockSession(privateKey)
  } finally {
    privateKey?.fill(0) // 异常路径也清零
    entropy.fill(0) // 根熵清零
    share1.bytes.fill(0)
    share2.bytes.fill(0)
  }
}

/** 确认短语：彻底删除必须输入的不可逆确认 */
export const WIPE_CONFIRM_PHRASE = 'PERMANENT DELETE'

/**
 * 安全删除单个文件：随机数据覆写 3 遍（尽力抹除，防常规恢复）→ unlink。
 * SSD 闪存级残余需取证设备才能读取，普通威胁模型下不可恢复。
 * 安全约束（全仓审计）：
 * - symlink 只 unlink 链接本身，绝不跟随/覆写目标（防目录外文件被破坏）
 * - 非普通文件（目录/FIFO/socket/设备）拒绝删除
 * - 硬链接（nlink>1）仅删除当前目录项，不覆写（防破坏其他链接指向的内容）
 * - 打开使用 O_NOFOLLOW + 打开后核验 dev/inode（防检查与打开之间被替换）
 * - 删除（unlink）失败抛错——调用方必须如实报告，不得静默吞掉
 */
async function secureDelete(file: string): Promise<void> {
  const lst = await fs.lstat(file)
  if (lst.isSymbolicLink()) {
    // 符号链接：只删链接本身，绝不跟随
    await fs.unlink(file)
    return
  }
  if (!lst.isFile()) {
    throw new Error(`拒绝删除非普通文件（目录/FIFO/socket/设备）: ${path.basename(file)}`)
  }
  if (lst.nlink > 1) {
    // 硬链接：覆写会同时破坏所有指向同一 inode 的其他目录项，仅删除当前项
    await fs.unlink(file)
    return
  }
  if (lst.size > 0) {
    // O_NOFOLLOW：即使 lstat 后路径被替换为 symlink，open 也拒绝跟随
    const fh = await fs.open(file, fs.constants.O_NOFOLLOW | fs.constants.O_RDWR)
    try {
      // 打开后核验 dev/inode——防检查与打开之间被替换（TOCTOU）
      const st = await fh.stat()
      if (st.dev !== lst.dev || st.ino !== lst.ino) {
        throw new Error(`文件在删除前被替换（inode 不一致），已中止: ${path.basename(file)}`)
      }
      for (let pass = 0; pass < 3; pass++) {
        let written = 0
        while (written < lst.size) {
          // 每个位置生成新随机块（防模式可预测）+ 分块防大文件内存
          const chunk = randomBytes(Math.min(64 * 1024, lst.size - written))
          const n = await fh.write(chunk, 0, chunk.length, written)
          written += typeof n === 'number' ? n : n.bytesWritten
        }
      }
      await fh.sync().catch(() => {})
    } finally {
      await fh.close().catch(() => {}) // 保证句柄释放
    }
  }
  await fs.unlink(file)
}

/** wipe 范围：all=本机全部密钥材料 / saved=仅'需用户保存'的明文备份（恢复码+助记词） */
export type WipeScope = 'all' | 'saved'

/** 恢复码本地存储状态（按 recovery-codes.txt 实况判断，供交互引导） */
export type RecoveryFileStatus = 'emailed' | 'local-only' | 'missing'

/** 检测恢复码存储状态：1 片=邮箱已送达（片③在邮箱）/ 2 片=本地集中 / 无文件 */
export async function getRecoveryFileStatus(): Promise<RecoveryFileStatus> {
  try {
    const content = await fs.readFile(recoveryFile(), 'utf8')
    const count = content.split('\n').filter((l) => /^(sn1|sn2)-/.test(l.trim())).length
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

/** 受控残留命名模式：事务备份 `.bak-<uuid>` 与 staging `.tmp-<uuid>`（防枚举到无关文件） */
const RESIDUAL_PATTERN = /\.(bak|tmp)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/** 清理钱包目录中受控残留 staging（.tmp-<uuid>）——防上次异常中断遗留明文恢复码/助记词 */
async function cleanupStaleStaging(): Promise<void> {
  try {
    const names = await fs.readdir(getHomeDir())
    for (const n of names) {
      if (RESIDUAL_PATTERN.test(n)) {
        await secureDelete(path.join(getHomeDir(), n)).catch(() => {})
      }
    }
  } catch {
    // 目录不存在等——无需清理
  }
}

/**
 * 彻底删除（不可恢复，覆写 3 遍 + unlink）：
 * - scope='saved'：仅删'需用户保存'的明文备份（recovery-codes.txt / mnemonic.txt）——
 *   本机不再有可被窃取的明文恢复码/助记词；钱包本体（设备片）保留，口令解锁继续可用
 * - scope='all'：删除本机全部密钥材料（device-share / recovery / mnemonic / metadata / unlock 会话）
 * - 两档均枚举删除受控残留（.bak-* 旧材料备份 / .tmp-* staging）——防「wipe 后旧明文仍可读」
 * - 删除失败不静默：仅 ENOENT（不存在）可跳过，其余错误聚合抛出（防「报告成功但密钥材料仍在」）
 * - 执行前必须输入确认短语 WIPE_CONFIRM_PHRASE（防误删）
 * - ⚠️ 调用前必须提醒用户：确认已保存恢复码/助记词（用户保存的那一份是唯一恢复途径）
 * @returns removed 为 basename 清单（展示用）
 */
export async function wipeWallet(confirmPhrase: string, scope: WipeScope = 'all'): Promise<{ removed: string[] }> {
  if (confirmPhrase !== WIPE_CONFIRM_PHRASE) {
    throw new Error('确认短语不匹配，已中止（防止误删）')
  }
  const removed: string[] = []
  const failures: { file: string; reason: string }[] = []
  const tryDelete = async (f: string, label: string) => {
    try {
      await secureDelete(f)
      removed.push(label)
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return // 仅「不存在」可跳过
      failures.push({ file: label, reason: (err as Error).message })
    }
  }
  const targets = scope === 'saved'
    ? [recoveryFile(), mnemonicFile()]
    : [metaFile(), deviceFile(), recoveryFile(), mnemonicFile()]
  for (const f of targets) {
    await tryDelete(f, path.basename(f))
  }
  // 枚举受控残留：.bak-* 旧材料备份（含明文恢复码/助记词旧版）+ .tmp-* staging——两档均清理
  try {
    const names = await fs.readdir(getHomeDir())
    for (const n of names) {
      if (RESIDUAL_PATTERN.test(n)) {
        await tryDelete(path.join(getHomeDir(), n), n)
      }
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      failures.push({ file: '钱包目录枚举', reason: (err as Error).message })
    }
  }
  if (scope === 'all') {
    // unlock/ 目录（令牌会话）
    try {
      const dir = getUnlockDir()
      const entries = await fs.readdir(dir)
      for (const e of entries) {
        await tryDelete(path.join(dir, e), `unlock/${e}`)
      }
      await fs.rmdir(dir).catch((err) => {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') failures.push({ file: 'unlock/', reason: (err as Error).message })
      })
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
        failures.push({ file: 'unlock/', reason: (err as Error).message })
      }
    }
  }
  // 任一目标删除失败 → 抛错（不返回「成功」清单），CLI/MCP 必须如实呈现失败
  if (failures.length > 0) {
    throw new Error(`删除失败（部分密钥材料未清除）：${failures.map((f) => `${f.file}: ${f.reason}`).join('；')}`)
  }
  return { removed }
}

/** 读取旧 metadata 中的地址（P1-3：仅 ENOENT 视为「不存在」返回 undefined；
 * JSON 损坏/字段缺失/权限错误等一律硬失败——防损坏 metadata 被误判为无钱包
 * 而绕过 init 防覆盖保护） */
async function readOldAddress(): Promise<string | undefined> {
  try {
    const meta = JSON.parse(await fs.readFile(metaFile(), 'utf8')) as { address?: string }
    const addr = meta.address
    if (typeof addr !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(addr)) {
      throw new Error(`metadata.json 损坏（缺少合法 address 字段）`)
    }
    return addr
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw err
  }
}
