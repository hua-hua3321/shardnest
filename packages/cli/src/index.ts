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
import { initWallet, getAddress, signMessage, restoreWallet, createUnlockToken } from './commands'

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
      const result = await initWallet(passphrase, email || undefined)
      console.log('\n✅ 钱包已创建')
      console.log(`地址: ${result.address}`)
      if (result.backupEmail) {
        console.log(`邮箱备份: ${result.backupEmail} → ${result.backupStatus === 'sent' ? '✅ 已发送' : '⚠️ 未配置 SMTP，请手动保存恢复码'}`)
      }
      console.log('\n⚠️  恢复码（请立即保存，丢失后设备损坏将无法找回）:')
      for (const code of result.recoveryCodes) console.log(`  ${code}`)
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
    case 'restore': {
      const passphrase = await promptSecret('设置新口令（>=12 位）: ')
      const c1 = await prompt('恢复码 1: ')
      const c2 = await prompt('恢复码 2: ')
      const result = await restoreWallet(passphrase, [c1, c2])
      console.log('\n✅ 钱包已恢复')
      console.log(`地址: ${result.address}`)
      console.log('\n⚠️  新恢复码（旧恢复码请作废销毁）:')
      for (const code of result.recoveryCodes) console.log(`  ${code}`)
      break
    }
    default:
      console.log('用法: shardnest [init|address|unlock|sign|restore]')
  }
}

main().catch((err) => {
  console.error('错误:', err.message)
  process.exit(1)
})
