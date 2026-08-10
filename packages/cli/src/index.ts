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
import { initWallet, getAddress, signMessage, restoreWallet } from './commands'

async function prompt(question: string): Promise<string> {
  process.stdout.write(question)
  for await (const line of console) {
    return line.trim()
  }
  return ''
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2)
  switch (cmd) {
    case 'init': {
      const passphrase = await prompt('设置口令（>=8 位，用于加密设备分片）: ')
      const result = await initWallet(passphrase)
      console.log('\n✅ 钱包已创建')
      console.log(`地址: ${result.address}`)
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
      const passphrase = await prompt('口令: ')
      const code = await prompt('恢复码: ')
      console.log(await signMessage(passphrase, code, args.join(' ')))
      break
    }
    case 'restore': {
      const passphrase = await prompt('设置新口令: ')
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
      console.log('用法: shardnest [init|address|sign|restore]')
  }
}

main().catch((err) => {
  console.error('错误:', err.message)
  process.exit(1)
})
