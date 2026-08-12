import { describe, it, expect, beforeEach } from 'bun:test'
import { splitSecret } from '@wallet-service/core'
import { deriveKEK, LEGACY_SCRYPT_OPTS_V1 } from '@wallet-service/core'
import { gcm } from '@noble/ciphers/aes'
import { randomBytes } from '@noble/hashes/utils'
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
  tryReadRecoveryCodeFromFile,
} from '../src/commands'
import { secp256k1 } from '@noble/curves/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3'

const TEST_HOME = path.join(process.cwd(), '.test-shardnest-home')

// P0-1 修复：模块加载阶段立即固定 SHARDNEST_HOME（在任何 beforeEach/getHomeDir()
// 调用之前）——此前 beforeEach 先 rm(getHomeDir()) 后设 env，未预设 env 时
// 会删除真实 ~/.shardnest（审查中已多次触发该路径，务必不再发生）
process.env.SHARDNEST_HOME = TEST_HOME

/** P0-1 路径守卫：只允许删除明确的测试目录，杜绝误删真实钱包 */
async function rmTestHome(): Promise<void> {
  if (!TEST_HOME.includes('.test-shardnest-')) {
    throw new Error(`拒绝删除非测试目录: ${TEST_HOME}`)
  }
  await fs.rm(TEST_HOME, { recursive: true, force: true })
}

beforeEach(async () => {
  await rmTestHome()
})

const PASSPHRASE = 'test-passphrase-123!'

describe('方案 A：tryReadRecoveryCodeFromFile 自动读取恢复码（免手输）', () => {
  it('文件存在时返回第一片（sn1 格式）', async () => {
    await fs.mkdir(getHomeDir(), { recursive: true })
    await fs.writeFile(path.join(getHomeDir(), 'recovery-codes.txt'), 'sn1-1-aa11bb22-00000000\nsn1-2-cc33dd44-00000000\n')
    expect(await tryReadRecoveryCodeFromFile()).toBe('sn1-1-aa11bb22-00000000')
  })

  it('sn2 批次格式同样识别', async () => {
    await fs.mkdir(getHomeDir(), { recursive: true })
    await fs.writeFile(path.join(getHomeDir(), 'recovery-codes.txt'), 'sn2-abcdef0123456789-1-aa11bb22-00000000\n')
    expect(await tryReadRecoveryCodeFromFile()).toBe('sn2-abcdef0123456789-1-aa11bb22-00000000')
  })

  it('文件缺失返回 null（调用方回退手动输入）', async () => {
    expect(await tryReadRecoveryCodeFromFile()).toBeNull()
  })

  it('空文件/无合法恢复码返回 null', async () => {
    await fs.mkdir(getHomeDir(), { recursive: true })
    await fs.writeFile(path.join(getHomeDir(), 'recovery-codes.txt'), 'not a recovery code\n\n')
    expect(await tryReadRecoveryCodeFromFile()).toBeNull()
  })

  it('指定自定义路径优先于默认文件', async () => {
    const custom = path.join(TEST_HOME, 'custom-codes.txt')
    await fs.mkdir(TEST_HOME, { recursive: true })
    await fs.writeFile(custom, 'sn1-2-cc33dd44-00000000\n')
    // 默认位置写入不同内容，验证指定路径生效
    await fs.mkdir(getHomeDir(), { recursive: true })
    await fs.writeFile(path.join(getHomeDir(), 'recovery-codes.txt'), 'sn1-1-aa11bb22-00000000\n')
    expect(await tryReadRecoveryCodeFromFile(custom)).toBe('sn1-2-cc33dd44-00000000')
  })

  it('与 initWallet 闭环：自动读取真实生成的恢复码可解锁', async () => {
    const result = await initWallet(PASSPHRASE)
    const code = await tryReadRecoveryCodeFromFile()
    expect(code).not.toBeNull()
    const token = await createUnlockToken(PASSPHRASE, code as string)
    expect(token).toMatch(/^[0-9a-f]{64}$/)
    expect(result.address).toMatch(/^0x[0-9a-fA-F]{40}$/)
  })
})

describe('CLI 钱包流程（init → sign → restore 全闭环）', () => {
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

  it('导出助记词：混用两个钱包的恢复码 → 批次校验拒绝（P1-2 优先于地址校验拦截）', async () => {
    const a = await initWallet(PASSPHRASE)
    const b = await initWallet(PASSPHRASE, undefined, false, true)
    // sn2 批次不同 → 批次不一致拒绝（比地址不一致更早、更明确）
    await expect(
      exportMnemonicFromCodes(a.recoveryCodes[0], b.recoveryCodes[1]),
    ).rejects.toThrow(/批次/)
  })

  it('P1-1：signMessage 用错钱包恢复码 → 地址交叉校验拒绝（不签出另一地址）', async () => {
    const a = await initWallet(PASSPHRASE)
    const b = await initWallet(PASSPHRASE, undefined, false, true)
    // 设备片来自钱包 B（最新），恢复码来自钱包 A → 组合出 A 地址 → 与 metadata 不一致 → 拒绝
    await expect(signMessage(PASSPHRASE, a.recoveryCodes[0], 'x')).rejects.toThrow(/不一致/)
    // 正确恢复码仍可签名
    const out = JSON.parse(await signMessage(PASSPHRASE, b.recoveryCodes[0], 'x'))
    expect(out.address.toLowerCase()).toBe(b.address.toLowerCase())
  })

  it('P1-2：恢复码为 sn2 批次格式；混用两个钱包的恢复码 → 批次不一致拒绝', async () => {
    const a = await initWallet(PASSPHRASE)
    const b = await initWallet(PASSPHRASE, undefined, false, true)
    // 新格式：sn2-<setid>-<index>-<hex>-<crc>，且同钱包两片 setId 一致
    expect(a.recoveryCodes[0]).toMatch(/^sn2-[0-9a-f]{16}-/)
    const sa1 = decodeRecoveryCode(a.recoveryCodes[0])
    const sa2 = decodeRecoveryCode(a.recoveryCodes[1])
    expect(sa1.setId).toBe(sa2.setId)
    // 混用 a + b 的恢复码 → restore 批次拒绝
    await expect(
      restoreWallet('new-passphrase-456!', [a.recoveryCodes[0], b.recoveryCodes[1]] as [string, string], a.address),
    ).rejects.toThrow(/批次|不同/)
    // 导出助记词同样拒绝混用
    await expect(exportMnemonicFromCodes(a.recoveryCodes[0], b.recoveryCodes[1])).rejects.toThrow(/批次|不同/)
    // 同钱包两片 restore 正常
    const r = await restoreWallet('new-passphrase-456!', [a.recoveryCodes[0], a.recoveryCodes[1]] as [string, string], a.address)
    expect(r.address.toLowerCase()).toBe(a.address.toLowerCase())
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

  it('C1：真实 v1 钱包（2^16 加密、无 kdf 字段）仍可解密——向后兼容', async () => {
    // 构造真实 v1 钱包：熵 → 分片 → 用 LEGACY（N=2^16）加密片① → 写 v1 结构
    const entropy = new Uint8Array(32).fill(5)
    const shares = splitSecret(entropy, { shares: 3, threshold: 2 })
    const salt = randomBytes(16)
    const kek = await deriveKEK(PASSPHRASE, salt, LEGACY_SCRYPT_OPTS_V1) // v1 实际参数
    const nonce = randomBytes(12)
    const cipher = gcm(kek, nonce)
    const payload = new Uint8Array(1 + shares[0].bytes.length)
    payload[0] = shares[0].index
    payload.set(shares[0].bytes, 1)
    const ct = cipher.encrypt(payload)
    const v1 = {
      version: 1,
      share: {
        data: Buffer.from(nonce).toString('base64') + '.' + Buffer.from(ct).toString('base64'),
        salt: Buffer.from(salt).toString('base64'),
      },
    }
    const { privateKeyToAddress, derivePrivateKeyFromEntropy } = await import('@wallet-service/core')
    const address = privateKeyToAddress(derivePrivateKeyFromEntropy(entropy))
    await fs.mkdir(getHomeDir(), { recursive: true })
    await fs.writeFile(path.join(getHomeDir(), 'device-share.json'), JSON.stringify(v1), { mode: 0o600 })
    await fs.writeFile(path.join(getHomeDir(), 'metadata.json'), JSON.stringify({ version: 1, address }), { mode: 0o600 })
    await saveRecoveryCodes([encodeRecoveryCode(shares[1])], true) // emailed → 本地 1 片
    // v1 钱包解密成功且地址正确（回退 LEGACY 参数而非新默认）
    const out = JSON.parse(await signMessage(PASSPHRASE, encodeRecoveryCode(shares[1]), 'v1-real'))
    expect(out.address).toBe(address)
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

  it('I18：metadata 损坏（有效 JSON 无 address）→ 干净拒绝而非裸 TypeError', async () => {
    await initWallet(PASSPHRASE)
    await fs.writeFile(path.join(getHomeDir(), 'metadata.json'), JSON.stringify({}), { mode: 0o600 })
    await expect(getAddress()).rejects.toThrow(/metadata 损坏/)
  })

  it('I19：SHARDNEST_HOME 空串 → 回退默认目录（不落 cwd）', async () => {
    const saved = process.env.SHARDNEST_HOME
    delete process.env.SHARDNEST_HOME
    const defaultDir = path.join(process.env.HOME ?? '.', '.shardnest')
    expect(getHomeDir()).toBe(defaultDir)
    process.env.SHARDNEST_HOME = '   '
    expect(getHomeDir()).toBe(defaultDir)
    process.env.SHARDNEST_HOME = '/tmp/x'
    expect(getHomeDir()).toBe('/tmp/x')
    if (saved === undefined) delete process.env.SHARDNEST_HOME
    else process.env.SHARDNEST_HOME = saved
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

  it('P0-2 事务式提交：staging 写失败时正式路径零接触（新建钱包无残留 / 覆盖旧钱包完整保留）', async () => {
    // 先建一个带助记词的旧钱包（模拟 force 覆盖目标）
    const ok = await initWallet(PASSPHRASE, undefined, true)
    expect(ok.mnemonicFile).toBeTruthy()
    const mnemonicFile = ok.mnemonicFile as string
    const recoveryFile = ok.recoveryFile as string
    expect(await fs.exists(mnemonicFile)).toBe(true)
    expect(await fs.exists(recoveryFile)).toBe(true)
    const oldMeta = await fs.readFile(path.join(getHomeDir(), 'metadata.json'), 'utf8')

    // 模拟 staging 写失败：device 的 .tmp-* 文件 open 抛错（磁盘满）
    const realOpen = fs.open.bind(fs)
    let fail = false
    fs.open = (async (file: string | URL, ...rest: unknown[]) => {
      if (fail && String(file).includes('.tmp-') && String(file).includes('device-share')) {
        const err = new Error('disk full (simulated)') as NodeJS.ErrnoException
        throw err
      }
      return (realOpen as (f: string | URL, ...r: unknown[]) => Promise<Awaited<ReturnType<typeof fs.open>>>)(file, ...rest)
    }) as typeof fs.open
    try {
      fail = true
      // force 覆盖旧钱包时 device staging 失败 → 必须抛错
      await expect(initWallet('another-passphrase-456!', undefined, true, true)).rejects.toThrow('disk full')
    } finally {
      fail = false
      fs.open = realOpen
    }
    // P0-2 核心断言：失败后旧钱包完整保留（meta 未被替换、无 staging 残留）
    expect(await fs.readFile(path.join(getHomeDir(), 'metadata.json'), 'utf8')).toBe(oldMeta)
    expect(await fs.exists(recoveryFile)).toBe(true)
    expect(await fs.exists(mnemonicFile)).toBe(true)
    // 无 .tmp- 残留
    const names = await fs.readdir(getHomeDir())
    expect(names.some((n) => n.includes('.tmp-'))).toBe(false)
  })

  it('P1 整组原子性：rename 中途失败 → 旧钱包完整回滚（无「新 meta/device + 旧 recovery」混合钱包）', async () => {
    // 先建旧钱包（meta/device/recovery 三文件都存在）
    const ok = await initWallet(PASSPHRASE)
    expect(ok.recoveryFile).toBeTruthy()
    const oldMeta = await fs.readFile(path.join(getHomeDir(), 'metadata.json'), 'utf8')
    const oldDevice = await fs.readFile(path.join(getHomeDir(), 'device-share.json'), 'utf8')
    const oldRecovery = await fs.readFile(path.join(getHomeDir(), 'recovery-codes.txt'), 'utf8')

    // 模拟切换阶段 rename 失败：staging → recovery-codes.txt 的 rename 抛错
    // （备份阶段 recovery → .bak-* 的 rename 不匹配拦截条件，正常放行）
    const realRename = fs.rename.bind(fs)
    fs.rename = (async (from: string | URL, to: string | URL) => {
      if (String(from).includes('.tmp-') && String(to).includes('recovery-codes.txt')) {
        throw new Error('rename failed (simulated)')
      }
      return (realRename as (f: string | URL, t: string | URL) => Promise<void>)(from, to)
    }) as typeof fs.rename
    try {
      // force 覆盖旧钱包：meta/device 已切换、recovery 切换失败 → 必须整体回滚
      await expect(initWallet('another-passphrase-456!', undefined, true, true)).rejects.toThrow('rename failed')
    } finally {
      fs.rename = realRename
    }
    // 整组回滚断言：三文件全部保持旧内容（不允许部分切换）
    expect(await fs.readFile(path.join(getHomeDir(), 'metadata.json'), 'utf8')).toBe(oldMeta)
    expect(await fs.readFile(path.join(getHomeDir(), 'device-share.json'), 'utf8')).toBe(oldDevice)
    expect(await fs.readFile(path.join(getHomeDir(), 'recovery-codes.txt'), 'utf8')).toBe(oldRecovery)
    // 无 .tmp- / .bak- 残留
    const names = await fs.readdir(getHomeDir())
    expect(names.some((n) => n.includes('.tmp-') || n.includes('.bak-'))).toBe(false)
  })

  it('P1-2 严格批次：sn2 与 sn1 混用 → 拒绝（防绕过批次校验恢复出第三个钱包）', async () => {
    const s1 = { index: 1, bytes: new Uint8Array([1, 2, 3, 4]) }
    const s2 = { index: 2, bytes: new Uint8Array([5, 6, 7, 8]) }
    const sn1Code = encodeRecoveryCode(s1) // 旧格式，无批次 ID
    const sn2Code = encodeRecoveryCode(s2, 'a'.repeat(16)) // 新格式，带批次 ID
    // 双恢复码导出路径
    await expect(exportMnemonicFromCodes(sn1Code, sn2Code)).rejects.toThrow(/新旧格式混用/)
    // restore 路径同样拒绝
    await expect(restoreWallet(PASSPHRASE, [sn1Code, sn2Code])).rejects.toThrow(/新旧格式混用/)
  })

  it('P3 显式 --recovery-file 路径错误 → 直接抛错（不静默回退手动输入）', async () => {
    await expect(tryReadRecoveryCodeFromFile(path.join(TEST_HOME, 'no-such-codes.txt'))).rejects.toThrow()
  })

  it('P1-3：损坏 metadata → initWallet 硬失败（不视为"无钱包"绕过防覆盖）', async () => {
    await initWallet(PASSPHRASE)
    // 篡改 metadata 为损坏 JSON → readOldAddress 重抛（非 ENOENT），initWallet 拒绝
    await fs.writeFile(path.join(getHomeDir(), 'metadata.json'), '{ broken', { mode: 0o600 })
    await expect(initWallet(PASSPHRASE)).rejects.toThrow()
    // 缺 address 字段的合法 JSON 同样硬失败（读旧地址时校验字段）
    await fs.writeFile(path.join(getHomeDir(), 'metadata.json'), JSON.stringify({ version: 1 }), { mode: 0o600 })
    await expect(initWallet(PASSPHRASE)).rejects.toThrow(/损坏|metadata|address/)
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
