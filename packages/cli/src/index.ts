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
import { initWallet, getAddress, signMessage, restoreWallet, createUnlockToken, restoreFromMnemonic, exportMnemonic, exportMnemonicFromCodes, wipeWallet, WIPE_CONFIRM_PHRASE, listSavedFiles } from './commands'
import { createPassphraseSession } from '@wallet-service/signer'

async function prompt(question: string): Promise<string> {
  process.stdout.write(question)
  for await (const line of console) {
    return line.trim()
  }
  return ''
}

/** 掩码口令输入（不回显，防肩窥/终端记录） */
function promptSecret(question: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true })
    const orig = rl._writeToOutput.bind(rl)
    rl._writeToOutput = (s: string) => {
      if (s === '\r\n' || s === '\n') orig(s)
      else orig('*')
    }
    rl.question(question, (ans) => {
      rl.close()
      resolve(ans)
    })
  })
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2)
  switch (cmd) {
    case 'passphrase-token': {
      // 本地输入口令 → 生成短期单次口令令牌（MCP wallet_create/restore 用，口令不进 LLM）
      const passphrase = await promptSecret('口令（>=12 位）: ')
      if (passphrase.length < 12) throw new Error('口令至少 12 位')
      const token = await createPassphraseSession(passphrase)
      console.log('\n🔑 口令令牌（5 分钟有效，单次使用，请勿在聊天中转发）:')
      console.log(token)
      break
    }
    case 'unlock': {
      const passphrase = await promptSecret('口令: ')
      const code = await prompt('恢复码: ')
      const token = await createUnlockToken(passphrase, code)
      console.log('\n🔓 解锁令牌（5 分钟有效，单次使用，请勿在聊天中转发）:')
      console.log(token)
      break
    }
    case 'init': {
      const passphrase = await promptSecret('设置口令（>=12 位，用于加密设备分片）: ')
      const email = await prompt('邮箱（可选，自动发送备份分片，回车跳过）: ')
      console.log('\n是否生成 24 词助记词备份？（默认不生成）')
      console.log('  ✅ 生成：单凭 24 词即可恢复钱包（最简恢复路径，行业标准格式）')
      console.log('  ⚠️  代价：助记词 = 完整私钥（单点）——泄露即资金丢失，无门限保护，需严格保管')
      console.log('  ℹ️  说明：12 词无法承载 32 字节私钥（容量不足），故仅支持 24 词；分片恢复码机制不受影响，二者并存')
      console.log('  💡 建议：普通用户不生成（分片已足够）；专业/高资产用户可生成并离线保管')
      const wantMnemonic = (await prompt('生成 24 词助记词？[y/N]: ')).toLowerCase()
      const result = await initWallet(passphrase, email || undefined, wantMnemonic === 'y' || wantMnemonic === 'yes')
      console.log('\n✅ 钱包已创建')
      console.log(`地址: ${result.address}`)
      if (result.backupEmail) {
        console.log(`邮箱备份: ${result.backupEmail} → ${result.backupStatus === 'sent' ? '✅ 已发送' : '⚠️ 未配置 SMTP，请手动保存恢复码'}`)
      }
      console.log('\n⚠️  恢复码（请立即保存，丢失后设备损坏将无法找回）:')
      for (const code of result.recoveryCodes) console.log(`  ${code}`)
      if (result.mnemonicFile) console.log(`\n🔑 24 词助记词已写入: ${result.mnemonicFile}（=完整私钥，请抄写后安全保管）`)
      if (result.note) console.log(`\n📝 ${result.note}`)
      break
    }
    case 'address': {
      console.log(await getAddress())
      break
    }
    case 'sign': {
      if (args.length === 0) throw new Error('用法: shardnest sign <message>')
      const passphrase = await promptSecret('口令: ')
      const code = await prompt('恢复码: ')
      console.log(await signMessage(passphrase, code, args.join(' ')))
      break
    }
    case 'wipe': {
      console.log('\n⚠️  删除为不可恢复操作（覆写 3 遍 + 删除）')
      console.log('\n📌 请选择删除范围：')
      console.log('  1) 仅删除「需用户保存」的明文备份（恢复码/助记词）')
      console.log('     本机不再有可被窃取的明文备份；钱包本体保留，口令解锁继续可用（推荐）')
      console.log('  2) 删除本机所有相关内容（钱包也删）')
      console.log('     本机不再持有任何密钥材料；需用您保存的恢复码/助记词重建')
      const scopeChoice = (await prompt('选择 [1/2]: ')).trim()
      const scope = scopeChoice === '2' ? 'all' : 'saved'
      if (scope === 'saved') {
        const savedFiles = await listSavedFiles()
        if (savedFiles.length === 0) {
          console.log('\nℹ️  当前没有「需保存」的明文备份文件（恢复码/助记词均不存在），无需删除')
          break
        }
        console.log('\n📄 将删除以下文件（覆写 3 遍，不可恢复）:')
        for (const name of savedFiles) console.log(`  - ${name}`)
      } else {
        console.log('\n📄 将删除本机全部密钥材料：device-share.json / recovery-codes.txt / mnemonic.txt / metadata.json / unlock 会话')
      }
      console.log('\n📌 执行前请确认：')
      console.log('    1. 恢复码/助记词已保存到安全位置（纸/密码管理器/邮箱备份）——这是唯一恢复途径')
      console.log('    2. 业务平台绑定等操作已处理完毕')
      const confirm = await prompt(`\n请输入确认短语「${WIPE_CONFIRM_PHRASE}」以继续: `)
      if (confirm !== WIPE_CONFIRM_PHRASE) {
        console.log('\n❌ 确认短语不匹配，已中止（未删除任何文件）')
        break
      }
      const { removed } = await wipeWallet(confirm, scope)
      console.log(`\n✅ 已彻底删除 ${removed.length} 个文件（覆写 3 遍 + 删除，不可恢复）:`)
      for (const name of removed) console.log(`  - ${name}`)
      if (scope === 'saved') {
        console.log('   钱包本体保留（设备片口令解锁继续可用）；如需删除钱包请重新执行 wipe 选择 2')
      } else {
        console.log('   使用您保存的恢复码（任意 2 片）或 24 词助记词，随时可重建钱包')
      }
      break
    }
    case 'mnemonic-export': {
      console.log('⚠️  导出的 24 词助记词 = 完整私钥（单点）：泄露即资金丢失，请离线严格保管')
      console.log('    选择分片来源：')
      const mode = (await prompt('a) 设备片+恢复码（需口令）  b) 两个恢复码  [a/b]: ')).toLowerCase()
      let result: { mnemonicFile: string; address: string }
      if (mode === 'b') {
        const c1 = await promptSecret('恢复码 1（掩码输入）: ')
        const c2 = await promptSecret('恢复码 2（掩码输入）: ')
        result = await exportMnemonicFromCodes(c1, c2)
      } else {
        const passphrase = await promptSecret('口令: ')
        const code = await promptSecret('恢复码（掩码输入）: ')
        result = await exportMnemonic(passphrase, code)
      }
      console.log('\n✅ 助记词已导出')
      console.log(`地址: ${result.address}（与本地钱包一致校验通过）`)
      console.log(`助记词文件: ${result.mnemonicFile}（24 词，请抄写后安全保管）`)
      break
    }
    case 'restore-mnemonic': {
      const passphrase = await promptSecret('设置新口令（>=12 位）: ')
      console.log('请输入 24 词助记词（以空格分隔）:')
      const mnemonic = await prompt('助记词: ')
      const expected = await prompt('期望地址（可选，强烈建议输入以校验恢复正确性，回车跳过）: ')
      const email = await prompt('邮箱（可选，自动更新邮箱备份分片，回车跳过）: ')
      const result = await restoreFromMnemonic(passphrase, mnemonic, expected || undefined, email || undefined)
      console.log('\n✅ 钱包已从助记词恢复')
      console.log(`地址: ${result.address}`)
      if (result.backupEmail) {
        console.log(`邮箱备份: ${result.backupEmail} → ${result.backupStatus === 'sent' ? '✅ 已发送' : '⚠️ 未配置 SMTP，请手动保存恢复码'}`)
      }
      console.log('\n⚠️  新恢复码（2-of-3 分片已重建）:')
      for (const code of result.recoveryCodes) console.log(`  ${code}`)
      if (result.note) console.log(`\n📝 ${result.note}`)
      break
    }
    case 'restore': {
      const passphrase = await promptSecret('设置新口令（>=12 位）: ')
      const c1 = await promptSecret('恢复码 1（掩码输入）: ')
      const c2 = await promptSecret('恢复码 2（掩码输入）: ')
      const expected = await prompt('期望地址（可选，强烈建议输入以校验恢复正确性，回车跳过）: ')
      const email = await prompt('邮箱（可选，自动更新邮箱备份分片，回车跳过）: ')
      const result = await restoreWallet(passphrase, [c1, c2], expected || undefined, email || undefined)
      console.log('\n✅ 钱包已恢复')
      console.log(`地址: ${result.address}`)
      if (result.backupEmail) {
        console.log(`邮箱备份: ${result.backupEmail} → ${result.backupStatus === 'sent' ? '✅ 已发送' : '⚠️ 未配置 SMTP，请手动保存恢复码'}`)
      }
      console.log('\n⚠️  新恢复码（旧恢复码请作废销毁）:')
      for (const code of result.recoveryCodes) console.log(`  ${code}`)
      if (result.backupStatus === 'sent') {
        console.log('\n📦 备份分布：片①设备（口令加密）+ 片②本地 + 片③已发邮箱——本机整体泄露无法动钱')
      } else {
        console.log('\n⚠️  当前备份分布：片①设备（口令加密）+ 片②③均在本机本地文件——本目录整体泄露即资金丢失，建议转移 1 片离线保存或配置邮箱备份')
      }
      if (result.note) console.log(`\n📝 ${result.note}`)
      break
    }
    default:
      console.log('用法: shardnest [init|address|passphrase-token|unlock|sign|restore|restore-mnemonic|mnemonic-export|wipe]')
  }
}

main().catch((err) => {
  console.error('错误:', err.message)
  process.exit(1)
})
