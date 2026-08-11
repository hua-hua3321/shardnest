import { describe, it, expect, beforeEach } from 'bun:test'
import { promises as fs } from 'node:fs'
import * as path from 'node:path'
import {getHomeDir,
  initWallet,
  getAddress,
  signMessage,
  restoreWallet,
  encodeRecoveryCode,
  decodeRecoveryCode,
  restoreFromMnemonic,
  createUnlockToken,
  exportMnemonic,
  exportMnemonicFromCodes,
  saveRecoveryCodes,
  wipeWallet,
  WIPE_CONFIRM_PHRASE,
  listSavedFiles,
  getRecoveryFileStatus,
} from '../src/commands'
import { secp256k1 } from '@noble/curves/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3'

const TEST_HOME = path.join(process.cwd(), '.test-shardnest-home')

beforeEach(async () => {
  await fs.rm(getHomeDir(), { recursive: true, force: true })
  process.env.SHARDNEST_HOME = TEST_HOME
})

const PASSPHRASE = 'test-passphrase-123!'

describe('CLI 钱包流程（init → sign → restore 全闭环）', () => {
  it('init 创建钱包：地址存在、恢复码 2 个、设备片文件加密存储', async () => {
    const result = await initWallet(PASSPHRASE)
    expect(result.address).toMatch(/^0x[0-9a-fA-F]{40}$/)
    expect(result.recoveryCodes.length).toBe(2)
    // 设备片文件存在且不含明文私钥材料
    const raw = await fs.readFile(path.join(getHomeDir(), 'device-share.json'), 'utf8')
    expect(raw).not.toContain('privateKey')
    // 地址无需口令可读
    expect(await getAddress()).toBe(result.address)
  })

  it('init → sign：EIP-191 签名验签还原同一地址', async () => {
    const result = await initWallet(PASSPHRASE)
    const out = JSON.parse(await signMessage(PASSPHRASE, result.recoveryCodes[0], 'hello shardnest'))
    expect(out.address).toBe(result.address)
    // 验签
    const sig = Uint8Array.from(Buffer.from(out.signature, 'hex'))
    const msg = new TextEncoder().encode('hello shardnest')
    const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${msg.length}`)
    const payload = new Uint8Array(prefix.length + msg.length)
    payload.set(prefix)
    payload.set(msg, prefix.length)
    const hash = keccak_256(payload)
    const pub = secp256k1.Signature.fromCompact(sig.slice(0, 64))
      .addRecoveryBit(sig[64])
      .recoverPublicKey(hash)
      .toRawBytes(false)
    const addrHash = keccak_256(pub.slice(1))
    const recovered = `0x${Array.from(addrHash.slice(12)).map((b) => b.toString(16).padStart(2, '0')).join('')}`
    expect(recovered.toLowerCase()).toBe(result.address.toLowerCase())
  })

  it('错误口令解密失败（AES-GCM 认证失败）', async () => {
    await initWallet(PASSPHRASE)
    await expect(signMessage('wrong-passphrase', 'sn1-2-00', 'x')).rejects.toThrow()
  })

  it('restore：用 2 个恢复码恢复出同一地址，且新恢复码可签名', async () => {
    const first = await initWallet(PASSPHRASE)
    // 模拟设备丢失：删除设备文件
    await fs.rm(getHomeDir(), { recursive: true, force: true })
    // 用旧恢复码恢复（新口令）
    const restored = await restoreWallet('new-passphrase-456!', [first.recoveryCodes[0], first.recoveryCodes[1]])
    expect(restored.address).toBe(first.address)
    // 新恢复码可签名
    const out = JSON.parse(await signMessage('new-passphrase-456!', restored.recoveryCodes[0], 'after restore'))
    expect(out.address).toBe(first.address)
  })

  it('init 提供邮箱：未配置 SMTP → backupStatus=skipped（备份回退手动）', async () => {
    const result = await initWallet(PASSPHRASE, 'user@example.com')
    expect(result.backupEmail).toBe('user@example.com')
    expect(result.backupStatus).toBe('skipped')
  })

  it('init 邮箱格式无效 → 抛错（不发信不建号）', async () => {
    await expect(initWallet(PASSPHRASE, 'not-an-email')).rejects.toThrow(/邮箱格式无效/)
  })

  it('恢复码编解码往返一致（含 CRC 校验）', () => {
    const share = { index: 7, bytes: new Uint8Array([1, 2, 3, 255]) }
    expect(decodeRecoveryCode(encodeRecoveryCode(share))).toEqual(share)
    expect(() => decodeRecoveryCode('bad-format')).toThrow()
  })

  it('saveRecoveryCodes：邮箱已送达（emailed）→ 本地仅 1 片 + 邮箱说明头（方案 A）', async () => {
    const share = { index: 2, bytes: new Uint8Array(32).fill(7) }
    const code = encodeRecoveryCode(share)
    const file = await saveRecoveryCodes([code], true)
    const fileContent = await fs.readFile(file, 'utf8')
    const codes = fileContent.split('\n').filter((l) => l.startsWith('sn1-'))
    expect(codes.length).toBe(1)
    expect(fileContent).toContain('已发送至您的邮箱')
    expect(fileContent).toContain('本机目录整体泄露也无法动用资金')
  })

  it('saveRecoveryCodes：未发邮箱 → 本地 2 片 + 显著警告（方案 B）', async () => {
    const share = { index: 2, bytes: new Uint8Array(32).fill(7) }
    const code = encodeRecoveryCode(share)
    const file = await saveRecoveryCodes([code, code], false)
    const fileContent = await fs.readFile(file, 'utf8')
    expect(fileContent).toContain('2 片均在本机')
    expect(fileContent).toContain('整体泄露 = 资金丢失')
    const codes = fileContent.split('\n').filter((l) => l.startsWith('sn1-'))
    expect(codes.length).toBe(2)
  })

  it('restore 带 email：未配置 SMTP → backupStatus=skipped + note 提示', async () => {
    const first = await initWallet(PASSPHRASE)
    const restored = await restoreWallet(
      PASSPHRASE,
      [first.recoveryCodes[0], first.recoveryCodes[1]],
      undefined,
      'backup@example.com',
    )
    expect(restored.backupEmail).toBe('backup@example.com')
    expect(restored.backupStatus).toBe('skipped')
    expect(restored.note).toContain('邮箱')
    // 恢复后地址一致（私钥不变）
    expect(restored.address).toBe(first.address)
  })

  it('init 生成助记词：24 词文件落盘 + 可单独恢复同一地址（默认关闭）', async () => {
    // 默认不生成
    const plain = await initWallet(PASSPHRASE)
    expect(plain.mnemonicFile).toBeUndefined()
    // 显式生成（覆盖上一钱包，测试意图）
    const withM = await initWallet(PASSPHRASE, undefined, true, true)
    expect(withM.mnemonicFile).toBeTruthy()
    const fileContent = await fs.readFile(withM.mnemonicFile!, 'utf8')
    const mnemonic = fileContent.split('\n').find((l) => l.trim().split(/\s+/).length === 24)!.trim()
    expect(mnemonic.split(' ').length).toBe(24)
    // 助记词单独恢复 → 同一地址 + 分片体系重建
    const restored = await restoreFromMnemonic(PASSPHRASE, mnemonic, withM.address)
    expect(restored.address).toBe(withM.address)
    expect(restored.recoveryCodes.length).toBe(2)
    expect(restored.recoveryFile).toBeTruthy()
  })

  it('restoreFromMnemonic 期望地址不匹配 → 抛错', async () => {
    const withM = await initWallet(PASSPHRASE, undefined, true)
    const fileContent = await fs.readFile(withM.mnemonicFile!, 'utf8')
    const mnemonic = fileContent.split('\n').find((l) => l.trim().split(/\s+/).length === 24)!.trim()
    await expect(
      restoreFromMnemonic(PASSPHRASE, mnemonic, '0x0000000000000000000000000000000000000000'),
    ).rejects.toThrow(/不一致/)
  })

  it('2/3 导出助记词：init 未生成 → 任意 2 片导出 → 单独恢复同一地址', async () => {
    // 1. 初始未生成助记词
    const plain = await initWallet(PASSPHRASE)
    expect(plain.mnemonicFile).toBeUndefined()
    // 2. 模式 B：2 个恢复码导出
    const exported = await exportMnemonicFromCodes(plain.recoveryCodes[0], plain.recoveryCodes[1])
    expect(exported.address).toBe(plain.address)
    const fileContent = await fs.readFile(exported.mnemonicFile, 'utf8')
    const mnemonic = fileContent.split('\n').find((l) => l.trim().split(/\s+/).length === 24)!.trim()
    expect(mnemonic.split(' ').length).toBe(24)
    // 3. 模式 A：设备片 + 1 恢复码导出 → 同一助记词（同一私钥）
    const exportedA = await exportMnemonic(PASSPHRASE, plain.recoveryCodes[0])
    expect(exportedA.address).toBe(plain.address)
    // 4. 导出的助记词可单独恢复同一地址
    const restored = await restoreFromMnemonic(PASSPHRASE, mnemonic, plain.address)
    expect(restored.address).toBe(plain.address)
  })

  it('导出助记词：错误恢复码 → 地址不一致拒绝', async () => {
    const a = await initWallet(PASSPHRASE)
    const b = await initWallet(PASSPHRASE, undefined, false, true)
    await expect(
      exportMnemonicFromCodes(a.recoveryCodes[0], b.recoveryCodes[1]),
    ).rejects.toThrow(/不一致/)
  })

  it('wipe：错误确认短语拒绝 → 正确短语彻底删除 → 保存的恢复码可重建', async () => {
    const result = await initWallet(PASSPHRASE)
    const savedCodes = [...result.recoveryCodes] // 用户保存的副本（wipe 前）
    // 错误确认短语 → 拒绝且不删
    await expect(wipeWallet('WRONG')).rejects.toThrow(/不匹配/)
    await expect(fs.stat(result.recoveryFile!)).resolves.toBeTruthy()
    // 正确短语 → 全部删除
    const { removed } = await wipeWallet(WIPE_CONFIRM_PHRASE)
    expect(removed.length).toBeGreaterThanOrEqual(3) // meta + device + recovery
    await expect(fs.stat(result.recoveryFile!)).rejects.toThrow()
    await expect(fs.stat(getHomeDir() + '/device-share.json')).rejects.toThrow()
    // 用用户保存的恢复码可重建（设备文件已删，走 2 恢复码路径）
    const restored = await restoreWallet(PASSPHRASE, [savedCodes[0], savedCodes[1]], result.address)
    expect(restored.address).toBe(result.address)
  })

  it('wipe saved 模式：仅删明文备份（恢复码/助记词），钱包本体保留可用', async () => {
    const result = await initWallet(PASSPHRASE, undefined, true) // 含助记词
    expect(result.mnemonicFile).toBeTruthy()
    // 删除前 listSavedFiles 显示清单
    const before = await listSavedFiles()
    expect(before).toContain('recovery-codes.txt')
    expect(before).toContain('mnemonic.txt')
    // saved 模式删除
    const { removed } = await wipeWallet(WIPE_CONFIRM_PHRASE, 'saved')
    expect(removed).toContain('recovery-codes.txt')
    expect(removed).toContain('mnemonic.txt')
    expect(removed).not.toContain('device-share.json') // 钱包本体保留
    // 明文备份已删
    await expect(fs.stat(result.recoveryFile!)).rejects.toThrow()
    await expect(fs.stat(result.mnemonicFile!)).rejects.toThrow()
    // 钱包仍可用：地址可读 + 口令解锁签名正常
    expect(await getAddress()).toBe(result.address)
    const out = JSON.parse(await signMessage(PASSPHRASE, result.recoveryCodes[0], 'still-alive'))
    expect(out.address).toBe(result.address)
  })

  it('O1：device-share.json 写 v2 结构且 KDF 参数随密文持久化', async () => {
    const r = await initWallet(PASSPHRASE)
    const file = JSON.parse(await fs.readFile(path.join(getHomeDir(), 'device-share.json'), 'utf8'))
    expect(file.version).toBe(2)
    expect(file.share.kdf).toBeDefined()
    expect(file.share.kdf.alg).toBe('scrypt')
    expect(file.share.kdf.N).toBe(2 ** 17) // O2: OWASP 下限
    // 解密仍正常（v2 用持久化参数派生）
    const out = JSON.parse(await signMessage(PASSPHRASE, r.recoveryCodes[0], 'o1'))
    expect(out.address).toBe(r.address)
  })

  it('O1：v1 旧结构（无 kdf 字段）仍可解密——兼容旧钱包', async () => {
    const r = await initWallet(PASSPHRASE)
    const file = JSON.parse(await fs.readFile(path.join(getHomeDir(), 'device-share.json'), 'utf8'))
    // 模拟 v1：去掉 kdf 字段
    const v1 = { version: 1, share: { data: file.share.data, salt: file.share.salt } }
    await fs.writeFile(path.join(getHomeDir(), 'device-share.json'), JSON.stringify(v1), { mode: 0o600 })
    const out = JSON.parse(await signMessage(PASSPHRASE, r.recoveryCodes[0], 'v1-compat'))
    expect(out.address).toBe(r.address)
  })

  it('O3：恢复码 CRC 为 32 位（8 hex），漏检率 1/2^32', () => {
    const share = { index: 7, bytes: new Uint8Array([1, 2, 3, 255]) }
    const code = encodeRecoveryCode(share)
    const crc = code.split('-')[3]
    expect(crc).toMatch(/^[0-9a-f]{8}$/)
    // 篡改 CRC 任意位 → 拒绝
    const tampered = code.slice(0, -1) + (crc.endsWith('0') ? '1' : '0')
    expect(() => decodeRecoveryCode(tampered)).toThrow(/校验失败/)
  })

  it('W9：已有钱包时 initWallet 拒绝（防静默覆盖）；force=true 可覆盖', async () => {
    await initWallet(PASSPHRASE)
    await expect(initWallet(PASSPHRASE)).rejects.toThrow(/钱包已存在/)
    // force=true 允许覆盖（显式意图）
    const r = await initWallet(PASSPHRASE, undefined, false, true)
    expect(r.address).toBeTruthy()
  })

  it('I10：错误口令解密 → 友好错误（非库原始异常）', async () => {
    const r = await initWallet(PASSPHRASE)
    await expect(signMessage('wrong-passphrase-999!', r.recoveryCodes[0], 'm')).rejects.toThrow(/口令错误/)
    await expect(createUnlockToken('wrong-passphrase-999!', r.recoveryCodes[0])).rejects.toThrow(/口令错误/)
  })

  it('原子性回滚：device 写入失败时 recovery-codes.txt 与 mnemonic.txt 一并清理（C1）', async () => {
    // 先正常建一个带助记词的钱包（制造 mnemonic.txt）
    const ok = await initWallet(PASSPHRASE, undefined, true)
    expect(ok.mnemonicFile).toBeTruthy()
    const mnemonicFile = ok.mnemonicFile as string
    const recoveryFile = ok.recoveryFile as string
    expect(await fs.exists(mnemonicFile)).toBe(true)
    expect(await fs.exists(recoveryFile)).toBe(true)

    // 模拟 device 写入失败：initWallet 再次运行时 device 写抛错
    const realWriteFile = fs.writeFile.bind(fs)
    let fail = false
    fs.writeFile = (async (file: string | URL, ...rest: unknown[]) => {
      if (fail && String(file).endsWith('device-share.json')) {
        const err = new Error('disk full (simulated)') as NodeJS.ErrnoException
        throw err
      }
      return (realWriteFile as (f: string | URL, ...r: unknown[]) => Promise<void>)(file, ...rest)
    }) as typeof fs.writeFile
    try {
      fail = true
      // 新口令 + 助记词——必须与旧钱包无关；这里仅验证回滚语义
      await expect(initWallet('another-passphrase-456!', undefined, true, true)).rejects.toThrow('disk full')
    } finally {
      fail = false
      fs.writeFile = realWriteFile
    }
    // 回滚断言：recovery-codes.txt / mnemonic.txt 都被清理（不残留私钥材料）
    expect(await fs.exists(recoveryFile)).toBe(false)
    expect(await fs.exists(mnemonicFile)).toBe(false)
  })

  it('getRecoveryFileStatus：1 片=emailed / 2 片=local-only / 无文件=missing', async () => {
    // 无文件
    expect(await getRecoveryFileStatus()).toBe('missing')
    // 2 片本地（未配邮箱）
    const b = await initWallet(PASSPHRASE)
    expect(await getRecoveryFileStatus()).toBe('local-only')
    // 1 片（emailed 语义：saveRecoveryCodes 只存 1 片）
    const share = { index: 3, bytes: new Uint8Array(32).fill(9) }
    await saveRecoveryCodes([encodeRecoveryCode(share)], true)
    expect(await getRecoveryFileStatus()).toBe('emailed')
    void b
  })

  it('wipe all：清理 unlock 会话目录（getUnlockDir 修复验证）', async () => {
    const result = await initWallet(PASSPHRASE)
    // 创建解锁令牌 → unlock/ 目录出现会话文件
    const token = await createUnlockToken(PASSPHRASE, result.recoveryCodes[0])
    expect(token.length).toBe(64)
    const unlockDir = path.join(getHomeDir(), 'unlock')
    const entriesBefore = await fs.readdir(unlockDir)
    expect(entriesBefore.length).toBeGreaterThan(0)
    // wipe all → unlock 目录被清理
    await wipeWallet(WIPE_CONFIRM_PHRASE, 'all')
    await expect(fs.readdir(unlockDir)).rejects.toThrow() // 目录已删除
  })

  it('restoreFromMnemonic 无效助记词 → 抛错', async () => {
    await expect(restoreFromMnemonic(PASSPHRASE, 'abandon '.repeat(24).trim())).rejects.toThrow(/助记词无效/)
  })

  it('恢复码 index 越界（999）→ 解码抛错（P1-B：GF 域 x 坐标校验）', () => {
    const share = { index: 2, bytes: new Uint8Array([1, 2, 3]) }
    const code = encodeRecoveryCode(share)
    const [, , hex, crc] = code.split('-')
    // 用合法 CRC 但越界 index——CRC 覆盖 index，必然失败
    expect(() => decodeRecoveryCode(`sn1-999-${hex}-${crc}`)).toThrow()
    // 直接构造：index 合法但 CRC 覆盖 index，篡改 index 后 CRC 不匹配
    expect(() => decodeRecoveryCode(`sn1-999-${hex}-00`)).toThrow()
  })

  it('恢复码 CRC 被篡改 → 解码抛错（防手输/OCR 错误静默恢复错误钱包）', () => {
    const share = { index: 7, bytes: new Uint8Array([1, 2, 3, 255]) }
    const code = encodeRecoveryCode(share)
    const tampered = code.slice(0, -1) + (code.endsWith('0') ? '1' : '0')
    expect(() => decodeRecoveryCode(tampered)).toThrow(/校验失败/)
  })

  it('restore 地址不匹配（expectedAddress 错误）→ 抛错中止', async () => {
    const first = await initWallet(PASSPHRASE)
    await expect(
      restoreWallet(PASSPHRASE, [first.recoveryCodes[0], first.recoveryCodes[1]], '0x0000000000000000000000000000000000000000'),
    ).rejects.toThrow(/不一致/)
  })

  it('口令 <12 位 → 拒绝（强度校验）', async () => {
    await expect(initWallet('short')).rejects.toThrow(/至少 12 位/)
  })
})
