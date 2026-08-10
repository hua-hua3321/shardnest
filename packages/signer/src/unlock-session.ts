/**
 * 解锁会话（P0-1：口令/恢复码不进 LLM 的替代通道）
 *
 * 流程：
 * 1. CLI `shardnest unlock`：本地输入口令+恢复码 → 组合私钥
 *    → 生成短期单次解锁令牌（token），私钥用 token 派生 KEK 加密落盘（0600）
 *    → 终端只输出 token（高熵随机，非口令）
 * 2. MCP `signed_request_sign(signed_request, unlock_token)`：
 *    token 经 LLM 可接受（短期 5min、单次使用、仅签名权限、无法还原口令）
 * 3. 消费后文件即删（单次），TTL 过期自动失效
 *
 * 安全：口令与恢复码永不出现在 LLM 上下文/聊天记录；token 泄露的窗口与
 * 权限受限于「5 分钟 + 单次 + 本地 0600 文件 + 仍需平台背书+用户确认」。
 */
import { promises as fs } from 'node:fs'
import * as path from 'node:path'
import { gcm } from '@noble/ciphers/aes'
import { sha256 } from '@noble/hashes/sha256'
import { randomBytes, bytesToHex } from '@noble/hashes/utils'

export const UNLOCK_TTL_MS = 5 * 60 * 1000 // 5 分钟

export function getUnlockDir(): string {
  return path.join(process.env.SHARDNEST_HOME ?? path.join(process.env.HOME ?? '.', '.shardnest'), 'unlock')
}

/**
 * 创建解锁会话：私钥用 token 派生 KEK 加密落盘，返回 token。
 * @param privateKey 组合出的私钥（调用方负责清零）
 */
export async function createUnlockSession(privateKey: Uint8Array): Promise<string> {
  const token = bytesToHex(randomBytes(32))
  const kek = sha256(new TextEncoder().encode(token))
  const nonce = randomBytes(12)
  const cipher = gcm(kek, nonce)
  const ct = cipher.encrypt(privateKey)
  const dir = getUnlockDir()
  await fs.mkdir(dir, { recursive: true })
  const file = path.join(dir, `unlock-${token.slice(0, 8)}.bin`)
  await fs.writeFile(
    file,
    JSON.stringify({ v: 1, nonce: Buffer.from(nonce).toString('base64'), ct: Buffer.from(ct).toString('base64') }),
    { mode: 0o600 },
  )
  return token
}

/**
 * 消费解锁会话：验证 TTL → 解密私钥 → 删除文件（单次使用）。
 * @returns 私钥（调用方签名后必须 wipe/清零）
 */
export async function consumeUnlockSession(token: string): Promise<Uint8Array> {
  if (!/^[0-9a-f]{64}$/.test(token)) throw new Error('解锁令牌格式无效')
  const dir = getUnlockDir()
  const file = path.join(dir, `unlock-${token.slice(0, 8)}.bin`)
  let stat: Awaited<ReturnType<typeof fs.stat>>
  try {
    stat = await fs.stat(file)
  } catch {
    throw new Error('解锁会话不存在或已被使用')
  }
  if (Date.now() - stat.mtimeMs > UNLOCK_TTL_MS) {
    await fs.rm(file, { force: true })
    throw new Error('解锁会话已过期，请重新 unlock')
  }
  const data = JSON.parse(await fs.readFile(file, 'utf8')) as { nonce: string; ct: string }
  const kek = sha256(new TextEncoder().encode(token))
  const nonce = Uint8Array.from(Buffer.from(data.nonce, 'base64'))
  const ct = Uint8Array.from(Buffer.from(data.ct, 'base64'))
  const privKey = gcm(kek, nonce).decrypt(ct)
  await fs.rm(file, { force: true }) // 单次使用
  return privKey
}
