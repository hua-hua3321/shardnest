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
 * 清理过期会话文件（I6）：unlock/passphrase 令牌生成后未消费的 .bin 会永久
 * 堆积——MCP server 启动时调用。文件 AES-GCM 加密（不可爆破），清理目的为
 * 防堆积占空间 + 减少「此机有钱包且曾解锁」的文件名侧信道。
 */
export async function cleanupExpiredUnlockSessions(): Promise<number> {
  let removed = 0
  try {
    const dir = getUnlockDir()
    const names = await fs.readdir(dir)
    const now = Date.now()
    for (const name of names) {
      if (!name.endsWith('.bin')) continue
      const file = path.join(dir, name)
      try {
        const st = await fs.stat(file)
        if (now - st.mtimeMs > UNLOCK_TTL_MS) {
          await fs.rm(file, { force: true })
          removed++
        }
      } catch {
        // 单个文件异常不影响整体清理
      }
    }
  } catch {
    // 目录不存在等——无需清理
  }
  return removed
}

/** 会话类型：unlock=私钥解锁 / passphrase=创建或恢复口令（均单次 + TTL） */
export type SessionType = 'unlock' | 'passphrase'

function sessionPrefix(type: SessionType): string {
  return type === 'unlock' ? 'unlock' : 'passphrase'
}

/**
 * 创建会话：敏感材料用 token 派生 KEK 加密落盘（0600），返回 token。
 * @param material 敏感字节（私钥或口令编码；调用方负责清零）
 * @param type 会话类型（决定文件前缀，隔离语义）
 */
export async function createUnlockSession(material: Uint8Array, type: SessionType = 'unlock'): Promise<string> {
  const token = bytesToHex(randomBytes(32))
  const kek = sha256(new TextEncoder().encode(token))
  const nonce = randomBytes(12)
  const cipher = gcm(kek, nonce)
  const ct = cipher.encrypt(material)
  const dir = getUnlockDir()
  await fs.mkdir(dir, { recursive: true })
  const file = path.join(dir, `${sessionPrefix(type)}-${token.slice(0, 16)}.bin`) // 8 字节熵前缀，防本地枚举
  await fs.writeFile(
    file,
    JSON.stringify({ v: 1, nonce: Buffer.from(nonce).toString('base64'), ct: Buffer.from(ct).toString('base64') }),
    { mode: 0o600 },
  )
  return token
}

/** 创建口令会话（口令编码为 UTF-8 字节；MCP 侧消费后必须清零） */
export function createPassphraseSession(passphrase: string): Promise<string> {
  const bytes = new TextEncoder().encode(passphrase)
  return createUnlockSession(bytes, 'passphrase')
}

/**
 * 消费解锁会话：验证 TTL → 解密私钥 → 删除文件（单次使用）。
 * @returns 私钥（调用方签名后必须 wipe/清零）
 */
export async function consumeUnlockSession(token: string, type: SessionType = 'unlock'): Promise<Uint8Array> {
  if (!/^[0-9a-f]{64}$/.test(token)) throw new Error('解锁令牌格式无效')
  const dir = getUnlockDir()
  const file = path.join(dir, `${sessionPrefix(type)}-${token.slice(0, 16)}.bin`)
  // 原子消费（TOCTOU 防护）：先 rename 到消费中文件（原子操作），
  // 并发第二个消费方 rename 失败 → 单次语义严格成立
  const consuming = path.join(dir, `consuming-${sessionPrefix(type)}-${token.slice(0, 16)}.bin`)
  try {
    await fs.rename(file, consuming)
  } catch {
    throw new Error('解锁会话不存在或已被使用')
  }
  try {
    const stat = await fs.stat(consuming)
    if (Date.now() - stat.mtimeMs > UNLOCK_TTL_MS) {
      throw new Error('解锁会话已过期，请重新 unlock')
    }
    const data = JSON.parse(await fs.readFile(consuming, 'utf8')) as { nonce: string; ct: string }
    const kek = sha256(new TextEncoder().encode(token))
    const nonce = Uint8Array.from(Buffer.from(data.nonce, 'base64'))
    const ct = Uint8Array.from(Buffer.from(data.ct, 'base64'))
    return gcm(kek, nonce).decrypt(ct)
  } finally {
    await fs.rm(consuming, { force: true })
  }
}

/** 消费口令会话 → 返回口令明文（用后请立即脱离作用域） */
export async function consumePassphraseSession(token: string): Promise<string> {
  const bytes = await consumeUnlockSession(token, 'passphrase')
  const passphrase = new TextDecoder().decode(bytes)
  bytes.fill(0)
  return passphrase
}
