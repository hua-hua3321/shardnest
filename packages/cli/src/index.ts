#!/usr/bin/env bun
/**
 * shardnest CLI — 人工场景：初始化 / 地址 / 签名 / 恢复
 *
 * 用法：
 *   shardnest init        # 生成钱包，输出恢复码（务必保存！）
 *   shardnest address     # 显示地址
 *   shardnest sign <msg>  # 解锁并 EIP-191 签名（口令 + 恢复码）
 *   shardnest restore     # 输入 2 个恢复码恢复（新设备/口令丢失）
 */
import * as readline from 'node:readline'
import { initWallet, getAddress, signMessage, restoreWallet, createUnlockToken, restoreFromMnemonic, exportMnemonic, exportMnemonicFromCodes, wipeWallet, WIPE_CONFIRM_PHRASE, listSavedFiles, getRecoveryFileStatus, tryReadRecoveryCodeFromFile, readRecoveryCodesFromFile, validatePassphrase, generatePlatformKeypair, savePlatformPrivateKey, splitRecoveryCodes } from './commands'
import { createPassphraseSession } from '@wallet-services/signer'
import { t } from './i18n'

/** 交互终端（TTY）时惰性创建 readline；管道/非 TTY 走 console 迭代器（Bun 下 readline 与管道 stdin 不兼容） */
let rl: import('node:readline').Interface | null = null
const getRl = () => {
  if (!rl) rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true })
  return rl
}

/** 普通输入 */
async function prompt(question: string): Promise<string> {
  if (process.stdin.isTTY) {
    return new Promise((resolve) => getRl().question(question, (ans) => resolve(ans.trim())))
  }
  process.stdout.write(question)
  for await (const line of console) {
    return line.trim()
  }
  return ''
}

/** 掩码口令输入（交互终端不回显；管道输入无终端回显，直接读取） */
async function promptSecret(question: string): Promise<string> {
  if (process.stdin.isTTY) {
    return new Promise((resolve) => {
      const r = getRl() as unknown as { _writeToOutput: (s: string) => void; question: (q: string, cb: (a: string) => void) => void }
      const orig = r._writeToOutput.bind(r)
      orig(question) // 修复：先正常输出提示文字（此前提问被一并掩码成 `*`，用户盲输）
      r._writeToOutput = (s: string) => {
        if (s === '\r\n' || s === '\n') orig(s)
        else orig('*')
      }
      r.question('', (ans) => {
        r._writeToOutput = orig
        resolve(ans)
      })
    })
  }
  return prompt(question)
}

/** 口令输入 + 即时强度校验（弱口令立即重试，避免填完所有字段才被拒） */
async function promptPassphrase(question: string): Promise<string> {
  for (;;) {
    const passphrase = await promptSecret(question)
    try {
      validatePassphrase(passphrase)
      return passphrase
    } catch (err) {
      console.log('⚠️  ' + (err as Error).message + t('，请重新输入', ', please retry'))
    }
  }
}

/** 恢复码来源引导：按本地存储状态提示第二因素应来自何处（防三片同地/双因素同地） */
async function printRecoverySourceGuide() {
  const status = await getRecoveryFileStatus()
  if (status === 'emailed') {
    console.log('  📦 ' + t('本地恢复码仅 1 片（另一片已在邮箱——建议作为第二因素）', 'Only 1 recovery code locally (the other is in your email — use it as the second factor)'))
    console.log('    ' + t('请输入恢复码；如需双因素分离，请从邮箱查看片③ 并手动输入（勿保存到本地文件）', 'Enter a recovery code; for separated 2FA, view share ③ in email and type it manually (do NOT save it to a local file)'))
  } else if (status === 'local-only') {
    console.log('  ⚠️  ' + t('本地集中存放 2 片恢复码（整体泄露=资金丢失）', '2 recovery codes stored together locally (full leak = funds lost)'))
    console.log('    ' + t('建议：先离线转移 1 片（纸/密码管理器），再从离线副本输入恢复码', 'Suggestion: move one share offline first (paper/password manager), then enter from the offline copy'))
  } else {
    console.log('  ℹ️  ' + t('未检测到本地恢复码文件——请从您保存的位置（纸/密码管理器/邮箱）输入恢复码', 'No local recovery file found — enter from where you saved it (paper/password manager/email)'))
  }
}

/** 恢复码来源选项解析（unlock/sign/mnemonic-export 共享）：
 * --manual 强制手动输入；--recovery-file <path> 指定恢复码文件（默认 recovery-codes.txt） */
function parseRecoveryOptions(args: string[]): { manual: boolean; recoveryFile?: string } {
  let manual = false
  let recoveryFile: string | undefined
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a === '--manual') manual = true
    else if (a === '--recovery-file') recoveryFile = args[++i]
  }
  return { manual, recoveryFile }
}

/** 恢复码获取（方案 A：免手输）：
 * 1) --recovery-file 指定文件 > 2) 默认自动读取 recovery-codes.txt > 3) 手动输入兑底
 * emailed 状态自动读取成功后仍提示双因素分离建议（尊重原安全引导） */
async function promptRecoveryCode(opts: { manual: boolean; recoveryFile?: string }): Promise<string> {
  if (!opts.manual) {
    const auto = await tryReadRecoveryCodeFromFile(opts.recoveryFile)
    if (auto) {
      const src = opts.recoveryFile ?? 'recovery-codes.txt'
      console.log('  📄 ' + t(`已自动读取恢复码（来源: ${src}；如需手动输入请用 --manual）`, `Auto-loaded recovery code (source: ${src}; use --manual to type it in)`))
      if ((await getRecoveryFileStatus()) === 'emailed') {
        console.log('    ' + t('提示：本地片②已使用；若需双因素分离，可用 --manual 从邮箱输入片③', 'Note: local share ② used; for 2FA separation, use --manual to type share ③ from email'))
      }
      return auto
    }
  }
  await printRecoverySourceGuide()
  return promptSecret(t('恢复码（掩码输入）: ', "Recovery code (masked): "))
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2)
  switch (cmd) {
    case 'passphrase-token': {
      // 本地输入口令 → 生成短期单次口令令牌（MCP wallet_create/restore 用，口令不进 LLM）
      const passphrase = await promptPassphrase(t('口令（>=12 位）: ', "Passphrase (>=12 chars): "))
      // P1-7: 令牌绑定操作用途——create 令牌只能用于 wallet_create，restore 令牌只能用于 wallet_restore
      console.log(t('令牌用途：', 'Token purpose:'))
      console.log(t('  [c] 创建钱包（wallet_create）', '  [c] Create wallet (wallet_create)'))
      console.log(t('  [r] 恢复钱包（wallet_restore）', '  [r] Restore wallet (wallet_restore)'))
      const purposeChoice = (await prompt(t('选择 [c/r]: ', 'Choose [c/r]: '))).trim().toLowerCase()
      const purpose = purposeChoice === 'r' ? 'restore' : 'create'
      const token = await createPassphraseSession(passphrase, purpose)
      console.log(t(`\n🔑 口令令牌（${purpose}，5 分钟有效，单次使用）：请粘贴到对应 MCP 工具调用中，勿转发给他人/其他平台`, `\n🔑 Passphrase token (${purpose}, valid 5 min, single-use): paste into the matching MCP tool call; do not forward to others/other platforms`))
      console.log(token)
      break
    }
    case 'unlock': {
      const ropts = parseRecoveryOptions(args)
      const passphrase = await promptSecret(t('口令: ', "Passphrase: "))
      const code = await promptRecoveryCode(ropts)
      const token = await createUnlockToken(passphrase, code)
      console.log(t('\n🔓 解锁令牌（5 分钟有效，单次使用）：请粘贴到 MCP 工具调用中，勿转发给他人/其他平台', '\n🔓 Unlock token (valid 5 min, single-use): paste into the MCP tool call; do not forward to others/other platforms'))
      console.log(token)
      break
    }
    case 'init-platform': {
      // 第三方平台接入：生成背书密钥对 + 输出配置片段（多平台白名单格式）
      const kp = generatePlatformKeypair()
      console.log(t('\n🎫 平台背书密钥对（第三方平台接入 shardnest）', '\n🎫 Platform endorsement keypair (third-party shardnest integration)'))
      console.log(t('\n平台地址（公开——配置到钱包服务白名单）:', '\nPlatform address (public — configure into wallet-service whitelist):'))
      console.log(`  ${kp.address}`)
      // 私钥交付：--out <path> 时 0600 落盘仅回路径（与恢复码/助记词同原则，不进终端/剪贴板）
      const outIdx = args.indexOf('--out')
      const outPath = outIdx >= 0 ? args[outIdx + 1] : undefined
      if (outPath) {
        const saved = await savePlatformPrivateKey(outPath, kp.privateKeyHex)
        console.log(t('\n平台私钥（机密——仅用于签发 signed_request）已写入:', '\nPlatform private key (SECRET — only for issuing signed_request) written to:'))
        console.log(`  ${saved} ${t('（0600）', ' (0600)')}`)
      } else {
        console.log(t('\n平台私钥（机密——仅用于签发 signed_request；请立即保存到 KMS/安全存储，勿泄露、勿进 LLM）:', '\nPlatform private key (SECRET — only for issuing signed_request; save to KMS/secure storage now, never leak, never send to an LLM):'))
        console.log(`  ${kp.privateKeyHex}`)
        console.log(t('  💡 建议加 --out <path> 以 0600 权限写入文件，避免私钥经终端/剪贴板传播', '  💡 Tip: use --out <path> to write the key to a file (0600) instead of exposing it via terminal/clipboard'))
      }
      console.log(t('\n=== 钱包服务侧配置（粘贴到用户本地 MCP 配置） ===', '\n=== Wallet-service side config (paste into the user\'s local MCP config) ==='))
      console.log(`  环境变量（单平台）：SHARDNEST_PLATFORM_ADDRESS=${kp.address}`)
      console.log(`  环境变量（多平台，逗号分隔追加）：SHARDNEST_PLATFORM_ADDRESS=0x已有平台A,${kp.address}`)
      console.log(`  配置文件（推荐多平台）：SHARDNEST_PLATFORM_CONFIG=~/.shardnest/platforms.json`)
      console.log(`    platforms.json 条目：{ "name": "your-platform", "address": "${kp.address}" }`)
      console.log(t('\n⚠️  私钥 = 平台背书身份：泄露后攻击者可伪造平台请求诱导用户签名恶意内容；请安全保管并支持轮换。', '\n⚠️  Private key = platform endorsement identity: a leak lets attackers forge platform requests and trick users into signing malicious content; store securely and support rotation.'))
      break
    }
    case 'split-recovery': {
      // 2-of-3 分离辅助：本地恢复码文件拆成两个独立文件（用户自选一份离线保存）
      const dir = args[0] ?? '.'
      const { files, codes } = await splitRecoveryCodes(dir)
      console.log(t('\n🔀 恢复码已拆分为独立文件（2-of-3 分离要求两片不同载体）:', '\n🔀 Recovery codes split into separate files (2-of-3 separation requires two distinct carriers):'))
      for (const f of files) console.log(`  - ${f} ${t('（0600）', ' (0600)')}`)
      console.log(t('\n📌 请立即：1) 把其中一份转移到离线位置（纸/密码管理器/另一台设备）；2) 转移后删除本机对应的那份副本；3) 原 recovery-codes.txt 可保留或删除（两片仍在同一位置即等于未分离）。', '\n📌 Next: 1) move ONE file offline (paper/password manager/another device); 2) delete the local copy of that share after moving; 3) the original recovery-codes.txt may be kept or deleted (two shares in one place = not separated).'))
      console.log(t('\n⚠️  当前两片仍在本地（含刚生成的两个文件）——删除其中一份本地副本前，请确认离线副本已安全保存。', '\n⚠️  Both shares are still local right now (including the two new files) — before deleting one local copy, make sure the offline copy is safely stored.'))
      if (codes.length < 2) console.log(t('\nℹ️  本地仅 1 片（另一片已发邮箱）：两片已天然分离，无需拆分。', '\nℹ️  Only 1 share local (the other is in email): already separated, no split needed.'))
      break
    }
    case 'init': {
      // W9: 已有钱包时警告 + 确认（防止误覆盖导致旧钱包资金永久丢失）
      const existingAddr = await getAddress().catch(() => null)
      if (existingAddr) {
        console.log('\n⚠️  ' + t(`已检测到钱包（${existingAddr}）。继续将生成全新钱包并覆盖设备分片——旧钱包若未备份恢复码，资金将永久丢失。`, `Wallet detected (${existingAddr}). Continuing creates a NEW wallet and overwrites the device share — if the old wallet's recovery codes were not saved, its funds are permanently lost.`))
        const ok = await prompt(t('确认重新创建？输入 yes 继续: ', 'Confirm recreate? type yes: '))
        if (ok.toLowerCase() !== 'yes') {
          console.log(t('已取消', 'Cancelled'))
          break
        }
      }
      const passphrase = await promptPassphrase(t('设置口令（>=12 位，用于加密设备分片）: ', "Set passphrase (>=12 chars, encrypts device share): "))
      const email = await prompt(t('邮箱（可选，自动发送备份分片——注意：邮件商可看到该明文分片（单片零信息量），回车跳过）: ', "Email (optional, auto-sends backup share — note: the mail provider can see this plaintext share (single share = zero info); Enter to skip): "))
      console.log('\n' + t('是否生成 24 词助记词备份？（默认不生成）', "Generate a 24-word mnemonic backup? (default: No)"))
      console.log(t('  ✅ 生成：单凭 24 词即可恢复钱包（最简恢复路径）。标准 BIP-39/44 语义（m/44\'/60\'/0\'/0/0）——可导入 MetaMask 等主流钱包恢复同一地址', "  ✅ Yes: recover with just the 24 words (simplest path). Standard BIP-39/44 semantics (m/44'/60'/0'/0/0) — importable into MetaMask etc. for the same address"))
      console.log(t('  ⚠️  代价：助记词 = 完整私钥（单点）——泄露即资金丢失，无门限保护，需严格保管', "  ⚠️ Cost: mnemonic = full private key (single point) — leak means total loss, no threshold protection"))
      console.log(t('  ℹ️  说明：钱包根=32 字节熵，分片保护熵；24 词=熵的标准 BIP-39 编码，可随时从任意 2 片导出。12 词无法承载 32 字节熵（容量不足）；分片恢复码机制不受影响，二者并存', "  ℹ️ Note: wallet root = 32-byte entropy (protected by 2-of-3 shares); the 24 words are its standard BIP-39 encoding, exportable from any 2 shares. 12 words cannot hold 32 bytes; the share system is unaffected and both coexist."))
      console.log(t('  💡 建议：普通用户不生成（分片已足够）；专业/高资产用户可生成并离线保管', "  💡 Tip: regular users skip (shares are enough); power users may generate and store offline"))
      const wantMnemonic = (await prompt(t('生成 24 词助记词？[y/N]: ', "Generate 24-word mnemonic? [y/N]: "))).toLowerCase()
      const result = await initWallet(passphrase, email || undefined, wantMnemonic === 'y' || wantMnemonic === 'yes')
      console.log('\n✅ ' + t('钱包已创建', "Wallet created"))
      console.log(`${t('地址: ', "Address: ")}${result.address}`)
      if (result.backupEmail) {
        console.log(`${t('邮箱备份: ', "Email backup: ")}${result.backupEmail} → ${result.backupStatus === 'sent' ? t('✅ 已发送', "✅ Sent") : t('⚠️ 未配置 SMTP，请手动保存恢复码', "⚠️ SMTP not configured; save recovery codes manually")}`)
      }
      console.log('\n⚠️  ' + t('恢复码（请立即保存，丢失后设备损坏将无法找回）:', "Recovery codes (save now; if the device is lost they cannot be recovered):"))
      for (const code of result.recoveryCodes) console.log(`  ${code}`)
      if (result.mnemonicFile) console.log(`\n🔑 ${t('24 词助记词已写入: ', "24-word mnemonic written to: ")}${result.mnemonicFile}${t('（=完整私钥，请抄写后安全保管）', " (= full private key; write it down and store securely)")}`)
      if (result.note) console.log(`\n📝 ${result.note}`)
      break
    }
    case 'address': {
      console.log(await getAddress())
      break
    }
    case 'sign': {
      const ropts = parseRecoveryOptions(args)
      // 过滤选项参数（含 --recovery-file 的值），剩余拼接为签名消息
      const msgParts: string[] = []
      for (let i = 0; i < args.length; i++) {
        const a = args[i]
        if (a === '--manual') continue
        if (a === '--recovery-file') {
          i++ // 跳过文件路径值
          continue
        }
        msgParts.push(a)
      }
      const message = msgParts.join(' ').trim()
      if (!message) throw new Error(t('用法: shardnest sign <message> [--manual] [--recovery-file <path>]', "Usage: shardnest sign <message> [--manual] [--recovery-file <path>]"))
      const passphrase = await promptSecret(t('口令: ', "Passphrase: "))
      const code = await promptRecoveryCode(ropts)
      console.log(await signMessage(passphrase, code, message))
      break
    }
    case 'wipe': {
      console.log('\n⚠️  ' + t('删除为不可恢复操作（覆写 3 遍 + 删除）', "Deletion is irreversible (3× overwrite + delete)"))
      console.log('\n📌 ' + t('请选择删除范围：', "Choose deletion scope:"))
      console.log(t('  1) 仅删除「需用户保存」的明文备份（恢复码/助记词）', '  1) Delete only must-save plaintext backups (recovery codes/mnemonic)'))
      console.log(t('     本机不再有可被窃取的明文备份；钱包本体保留，口令解锁继续可用（推荐）', "     No more stealable plaintext backups; wallet stays usable (recommended)"))
      console.log(t('  2) 删除本机所有相关内容（钱包也删）', "  2) Delete everything on this machine (wallet too)"))
      console.log(t('     本机不再持有任何密钥材料；需用您保存的恢复码/助记词重建', "     No key material left; rebuild from your saved codes/mnemonic"))
      const scopeChoice = (await prompt(t('选择 [1/2]: ', "Choose [1/2]: "))).trim()
      const scope = scopeChoice === '2' ? 'all' : 'saved'
      if (scope === 'saved') {
        const savedFiles = await listSavedFiles()
        if (savedFiles.length === 0) {
          console.log('\nℹ️  ' + t('当前没有「需保存」的明文备份文件（恢复码/助记词均不存在），无需删除', 'No must-save plaintext backup files exist; nothing to delete'))
          break
        }
        console.log('\n📄 ' + t('将删除以下文件（覆写 3 遍，不可恢复）:', "The following files will be deleted (3× overwrite, irreversible):"))
        for (const name of savedFiles) console.log(`  - ${name}`)
      } else {
        console.log('\n📄 ' + t('将删除本机全部密钥材料：device-share.json / recovery-codes.txt / mnemonic.txt / metadata.json / unlock 会话', "All key material will be deleted: device-share.json / recovery-codes.txt / mnemonic.txt / metadata.json / unlock sessions"))
      }
      console.log('\n📌 ' + t('执行前请确认：', "Before proceeding, confirm:"))
      console.log(t('    1. 恢复码/助记词已保存到安全位置（纸/密码管理器/邮箱备份）——这是唯一恢复途径', "    1. Recovery codes/mnemonic saved somewhere safe (paper/password manager/email) — this is the only recovery path"))
      console.log(t('    2. 业务平台绑定等操作已处理完毕', "    2. Business platform bindings etc. are finalized"))
      const confirm = await prompt('\n' + t('请输入确认短语「', 'Type the confirm phrase "') + WIPE_CONFIRM_PHRASE + t('」以继续: ', '" to continue: '))
      if (confirm !== WIPE_CONFIRM_PHRASE) {
        console.log('\n❌ ' + t('确认短语不匹配，已中止（未删除任何文件）', "Confirm phrase mismatch, aborted (nothing deleted)"))
        break
      }
      const { removed } = await wipeWallet(confirm, scope)
      console.log(`\n✅ ${t('已彻底删除 ', "Permanently deleted ")}${removed.length}${t(' 个文件（覆写 3 遍 + 删除，不可恢复）:', " files (3× overwrite + delete, irreversible):")}`)
      for (const name of removed) console.log(`  - ${name}`)
      if (scope === 'saved') {
        console.log(t('   钱包本体保留（设备片口令解锁继续可用）；如需删除钱包请重新执行 wipe 选择 2', "   Wallet kept (device share unlock still works); to delete wallet run wipe and choose 2"))
      } else {
        console.log(t('   使用您保存的恢复码（任意 2 片）或 24 词助记词，随时可重建钱包', "   Rebuild anytime with your saved recovery codes (any 2) or the 24-word mnemonic"))
      }
      break
    }
    case 'mnemonic-export': {
      console.log(t('⚠️  导出的 24 词助记词 = 完整私钥（单点）：泄露即资金丢失，请离线严格保管', "⚠️  The exported 24-word mnemonic = full private key (single point): leak means total loss; store offline strictly"))
      console.log('    选择分片来源：')
      const mode = (await prompt(t('a) 设备片+恢复码（需口令）  b) 两个恢复码  [a/b]: ', "a) device share + recovery code (needs passphrase)  b) two recovery codes  [a/b]: "))).toLowerCase()
      let result: { mnemonicFile: string; address: string }
      if (mode === 'b') {
        const c1 = await promptSecret(t('恢复码 1（掩码输入）: ', "Recovery code 1 (masked): "))
        const c2 = await promptSecret(t('恢复码 2（掩码输入）: ', "Recovery code 2 (masked): "))
        result = await exportMnemonicFromCodes(c1, c2)
      } else {
        const ropts = parseRecoveryOptions(args)
        const passphrase = await promptSecret(t('口令: ', "Passphrase: "))
        const code = await promptRecoveryCode(ropts)
        result = await exportMnemonic(passphrase, code)
      }
      console.log('\n✅ ' + t('助记词已导出', "Mnemonic exported"))
      console.log(`${t('地址: ', "Address: ")}${result.address}${t('（与本地钱包一致校验通过）', " (verified against local wallet)")}`)
      console.log(`${t('助记词文件: ', "Mnemonic file: ")}${result.mnemonicFile}${t('（24 词，请抄写后安全保管）', " (24 words; write it down and store securely)")}`)
      break
    }
    case 'restore-mnemonic': {
      const passphrase = await promptPassphrase(t('设置新口令（>=12 位）: ', "Set new passphrase (>=12 chars): "))
      console.log(t('请输入 24 词助记词（以空格分隔）:', "Enter the 24-word mnemonic (space-separated):"))
      // 修复：助记词 = 完整私钥，掩码输入（此前明文回显到终端）
      const mnemonic = await promptSecret(t('助记词（掩码输入）: ', "Mnemonic (masked): "))
      const expected = await prompt(t('期望地址（旧版 sn1 恢复码在此环境必须提供，回车跳过仅限带批次标识的 sn2）: ', "Expected address (legacy sn1 codes REQUIRE this here; Enter to skip only with sn2 batch codes): "))
      const email = await prompt(t('邮箱（可选，自动更新邮箱备份分片，回车跳过）: ', "Email (optional, auto-updates email backup share; Enter to skip): "))
      const result = await restoreFromMnemonic(passphrase, mnemonic, expected || undefined, email || undefined)
      console.log('\n✅ ' + t('钱包已从助记词恢复', "Wallet recovered from mnemonic"))
      console.log(`${t('地址: ', "Address: ")}${result.address}`)
      if (result.backupEmail) {
        console.log(`${t('邮箱备份: ', "Email backup: ")}${result.backupEmail} → ${result.backupStatus === 'sent' ? t('✅ 已发送', "✅ Sent") : t('⚠️ 未配置 SMTP，请手动保存恢复码', "⚠️ SMTP not configured; save recovery codes manually")}`)
      }
      console.log('\n⚠️  ' + t('新恢复码（2-of-3 分片已重建）:', "New recovery codes (2-of-3 shares rebuilt):"))
      for (const code of result.recoveryCodes) console.log(`  ${code}`)
      if (result.note) console.log(`\n📝 ${result.note}`)
      break
    }
    case 'restore': {
      const ropts = parseRecoveryOptions(args)
      const passphrase = await promptPassphrase(t('设置新口令（>=12 位）: ', "Set new passphrase (>=12 chars): "))
      // 恢复码获取：--recovery-file/自动读取优先（与 unlock/sign 一致），否则手动掩码输入
      let c1: string
      let c2: string
      if (!ropts.manual) {
        const auto = await tryReadRecoveryCodeFromFile(ropts.recoveryFile)
        if (auto) {
          const all = await readRecoveryCodesFromFile(ropts.recoveryFile)
          const src = ropts.recoveryFile ?? 'recovery-codes.txt'
          if (all.length >= 2) {
            console.log('  📄 ' + t(`已自动读取 2 个恢复码（来源: ${src}；如需手动输入请用 --manual）`, `Auto-loaded 2 recovery codes (source: ${src}; use --manual to type them in)`))
            c1 = all[0]
            c2 = all[1]
          } else {
            console.log('  📄 ' + t(`已自动读取 1 个恢复码（来源: ${src}）——本地仅 1 片，请从邮箱/离线副本输入第二片`, `Auto-loaded 1 recovery code (source: ${src}) — only 1 share local; type the second from email/offline copy`))
            c1 = auto
            c2 = await promptSecret(t('恢复码 2（掩码输入）: ', "Recovery code 2 (masked): "))
          }
        } else {
          await printRecoverySourceGuide()
          c1 = await promptSecret(t('恢复码 1（掩码输入）: ', "Recovery code 1 (masked): "))
          c2 = await promptSecret(t('恢复码 2（掩码输入）: ', "Recovery code 2 (masked): "))
        }
      } else {
        await printRecoverySourceGuide()
        c1 = await promptSecret(t('恢复码 1（掩码输入）: ', "Recovery code 1 (masked): "))
        c2 = await promptSecret(t('恢复码 2（掩码输入）: ', "Recovery code 2 (masked): "))
      }
      const expected = await prompt(t('期望地址（旧版 sn1 恢复码在此环境必须提供，回车跳过仅限带批次标识的 sn2）: ', "Expected address (legacy sn1 codes REQUIRE this here; Enter to skip only with sn2 batch codes): "))
      const email = await prompt(t('邮箱（可选，自动更新邮箱备份分片，回车跳过）: ', "Email (optional, auto-updates email backup share; Enter to skip): "))
      const result = await restoreWallet(passphrase, [c1, c2], expected || undefined, email || undefined)
      console.log('\n✅ ' + t('钱包已恢复', "Wallet recovered"))
      console.log(`${t('地址: ', "Address: ")}${result.address}`)
      if (result.backupEmail) {
        console.log(`${t('邮箱备份: ', "Email backup: ")}${result.backupEmail} → ${result.backupStatus === 'sent' ? t('✅ 已发送', "✅ Sent") : t('⚠️ 未配置 SMTP，请手动保存恢复码', "⚠️ SMTP not configured; save recovery codes manually")}`)
      }
      console.log('\n⚠️  ' + t('新恢复码（旧恢复码请作废销毁）:', "New recovery codes (destroy the old ones):"))
      for (const code of result.recoveryCodes) console.log(`  ${code}`)
      if (result.backupStatus === 'sent') {
        console.log('\n📦 ' + t('备份分布：片①设备（口令加密）+ 片②本地 + 片③已发邮箱——本机整体泄露无法动钱', "Backup layout: share ① device (passphrase-encrypted) + share ② local + share ③ emailed — full local compromise cannot move funds"))
      } else {
        console.log('\n⚠️  ' + t('当前备份分布：片①设备（口令加密）+ 片②③均在本机本地文件——本目录整体泄露即资金丢失，建议转移 1 片离线保存或配置邮箱备份', "Current layout: share ① device (passphrase-encrypted) + shares ②③ both local — full local compromise = funds lost; move one share offline or configure email"))
      }
      if (result.note) console.log(`\n📝 ${result.note}`)
      break
    }
    default:
      console.log(t('用法: shardnest [init|init-platform|split-recovery|address|passphrase-token|unlock|sign|restore|restore-mnemonic|mnemonic-export|wipe]\nunlock/sign/restore 支持: --manual（强制手输恢复码） --recovery-file <path>（指定恢复码文件）\ninit-platform 支持: --out <path>（平台私钥 0600 落盘，不进终端）', "Usage: shardnest [init|init-platform|split-recovery|address|passphrase-token|unlock|sign|restore|restore-mnemonic|mnemonic-export|wipe]\nunlock/sign/restore support: --manual (force manual recovery code input) --recovery-file <path> (custom codes file)\ninit-platform supports: --out <path> (write platform key to file 0600, not the terminal)"))
  }
}

main().catch((err) => {
  console.error(t('错误:', "Error:"), err.message)
  process.exit(1)
})
