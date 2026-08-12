/**
 * signed_request v1 — 平台背书签名请求（钱包服务与业务平台的唯一耦合点）
 *
 * 流程：
 * 1. 平台用自持私钥签发（issueSignedRequest）
 * 2. 钱包服务验签（verifySignedRequest）→ 弹窗确认 → 本地签名
 * 3. 平台用 verify-sdk 验证钱包返回的签名
 *
 * 防攻击：
 * - platform_signature：无平台私钥无法伪造背书
 * - nonce：一次性（平台侧原子消费），防重放
 * - expires_at：时效限制
 * - user_id / wallet_address：防跨用户/跨地址
 */
import { secp256k1 } from '@noble/curves/secp256k1'
import { keccak_256 } from '@noble/hashes/sha3'
import { recoverSigner } from '@wallet-services/verify-sdk'

export type SignedRequestAction = 'sign_message' | 'sign_tx' | 'bind_wallet' | 'withdraw_confirm'

export interface SignedRequest {
  v: 1
  action: SignedRequestAction
  intent_hash: string
  display: string
  user_id: string
  wallet_address: string
  nonce: string
  expires_at: number
  platform_signature: string
}

/**
 * 参与签名的字段（v..expires_at）——O5: length-prefixed 确定性二进制（类 RLP）。
 * 消除跨语言陷阱：UTF-8 字节 + 4 字节大端长度前缀，任何语言实现完全一致；
 * 整数固定 8 字节大端（无 JSON 整数/浮点歧义）。
 * 布局：
 *   v(1B) | action(len4+utf8) | intent_hash(len4+32B) | display(len4+utf8)
 *   | user_id(len4+utf8) | wallet_address(len4+20B) | nonce(len4+utf8) | expires_at(8B BE)
 */
export function canonicalBytes(req: Omit<SignedRequest, 'platform_signature'>): Uint8Array {
  const enc = new TextEncoder()
  const lp = (data: Uint8Array): Uint8Array => {
    const out = new Uint8Array(4 + data.length)
    new DataView(out.buffer).setUint32(0, data.length, false)
    out.set(data, 4)
    return out
  }
  const parts: Uint8Array[] = [
    Uint8Array.of(req.v),
    lp(enc.encode(req.action)),
    lp(new Uint8Array(Buffer.from(req.intent_hash.slice(0, 2) === '0x' ? req.intent_hash.slice(2) : req.intent_hash, 'hex'))),
    lp(enc.encode(req.display)),
    lp(enc.encode(req.user_id)),
    lp(new Uint8Array(Buffer.from(req.wallet_address.slice(0, 2) === '0x' ? req.wallet_address.slice(2) : req.wallet_address, 'hex'))),
    lp(enc.encode(req.nonce)),
  ]
  const exp = new Uint8Array(8)
  new DataView(exp.buffer).setBigUint64(0, BigInt(req.expires_at), false)
  parts.push(exp)
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

/** EIP-191 个人消息哈希（与 verify-sdk recoverSigner 完全一致，两端必须同构） */
export function personalMessageHash(message: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${message.length}`)
  const payload = new Uint8Array(prefix.length + message.length)
  payload.set(prefix)
  payload.set(message, prefix.length)
  return keccak_256(payload)
}

/**
 * P1-6: 钱包侧签名消息（域分离 + 请求上下文绑定）。
 * 格式 v2：length-prefixed 确定性二进制（消除冒号拼接的字段边界歧义）：
 *   `shardnest:signed_request:v2:` (16B) | wallet_address(lp) | platform_address(lp)
 *   | action(lp) | intent_hash(lp 32B) | nonce(lp) | expires_at(8B BE) | user_id(lp)
 * - 绑定 wallet_address / platform_address / action / intent_hash / nonce / expires_at / user_id——
 *   签名无法脱离原始请求传播：防跨请求复用（nonce）、跨钱包（wallet_address）、
 *   跨平台（platform_address）、跨用户（user_id）
 * - 4 字节大端长度前缀 + UTF-8 字节——nonce/user_id 含冒号或任意字符均无歧义
 * - MCP 签名端与平台验签端必须调用同一函数，杜绝手工拼串漂移
 * - 注：display 与 platform_signature 不进入签名——业务语义由 intent_hash 承诺（平台必须保证）；
 *   背书验签由 verifySignedRequest 独立完成（与钱包签名互为双闸门）
 */
export function walletSignMessage(req: Pick<SignedRequest, 'action' | 'intent_hash' | 'wallet_address' | 'nonce' | 'expires_at' | 'user_id'> & { platform_address: string }): Uint8Array {
  const enc = new TextEncoder()
  const lp = (s: string): Uint8Array => {
    const data = enc.encode(s)
    const out = new Uint8Array(4 + data.length)
    new DataView(out.buffer).setUint32(0, data.length, false)
    out.set(data, 4)
    return out
  }
  const parts: Uint8Array[] = [
    enc.encode('shardnest:signed_request:v2:'), // 域分离前缀（与背书签名 v1 区分）
    lp(req.wallet_address.toLowerCase()),
    lp(req.platform_address.toLowerCase()),
    lp(req.action),
    lp(req.intent_hash),
    lp(req.nonce),
    lp(req.expires_at.toString()),
    lp(req.user_id),
  ]
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

export interface IssueOptions {
  action: SignedRequestAction
  intentHash: string
  display: string
  userId: string
  walletAddress: string
  nonce: string
  expiresAt: number
}

/**
 * 平台侧签发（平台自持私钥调用；私钥只在这里被使用，用完即弃）
 */
export function issueSignedRequest(options: IssueOptions, platformPrivateKey: Uint8Array): SignedRequest {
  const base = {
    v: 1 as const,
    action: options.action,
    intent_hash: options.intentHash,
    display: options.display,
    user_id: options.userId,
    wallet_address: options.walletAddress,
    nonce: options.nonce,
    expires_at: options.expiresAt,
  }
  const hash = personalMessageHash(canonicalBytes(base))
  const sig = secp256k1.sign(hash, platformPrivateKey)
  const raw = sig.toCompactRawBytes()
  const out = new Uint8Array(65)
  out.set(raw)
  out[64] = sig.recovery ?? 0
  return { ...base, platform_signature: Buffer.from(out).toString('hex') }
}

export type SignedRequestError = 'INVALID_FORMAT' | 'EXPIRED' | 'BAD_SIGNATURE' | 'ACTION_NOT_ALLOWED'

export interface VerifyResult {
  ok: boolean
  /** 平台背书地址（验签还原） */
  platformAddress?: string
  error?: SignedRequestError
}

/**
 * 钱包侧验签（平台背书校验）：
 * 1. 结构校验（v/action/nonce/expires_at 格式）
 * 2. 时效校验（expires_at > now）
 * 3. 签名校验（还原平台地址，并与期望平台地址匹配）
 */
export function verifySignedRequest(
  req: unknown,
  expectedPlatformAddress: string,
  nowMs: number = Date.now(),
): VerifyResult {
  if (typeof req !== 'object' || req === null) return { ok: false, error: 'INVALID_FORMAT' }
  const r = req as SignedRequest
  const ACTIONS: readonly string[] = ['sign_message', 'sign_tx', 'bind_wallet', 'withdraw_confirm']
  if (r.v !== 1 || typeof r.action !== 'string' || !ACTIONS.includes(r.action) || typeof r.nonce !== 'string' || r.nonce.length < 16) {
    return { ok: false, error: 'INVALID_FORMAT' }
  }
  if (typeof r.user_id !== 'string' || r.user_id.length === 0 || r.user_id.length > 100) {
    return { ok: false, error: 'INVALID_FORMAT' }
  }
  // 字段格式校验（防垃圾字段进入 canonical 签名路径）
  if (typeof r.intent_hash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(r.intent_hash)) {
    return { ok: false, error: 'INVALID_FORMAT' }
  }
  if (typeof r.display !== 'string' || r.display.length === 0 || r.display.length > 200) {
    return { ok: false, error: 'INVALID_FORMAT' }
  }
  if (typeof r.wallet_address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(r.wallet_address)) {
    return { ok: false, error: 'INVALID_FORMAT' }
  }
  if (typeof r.expires_at !== 'number' || !Number.isInteger(r.expires_at) || r.expires_at * 1000 <= nowMs) {
    return { ok: false, error: 'EXPIRED' }
  }
  // P1-5: platform_signature 严格预校验（65 字节 r||s||v = 130 hex）——
  // 畸形输入（undefined/对象/非 hex/错误长度）直接结构化拒绝，不抛库异常
  if (typeof r.platform_signature !== 'string' || !/^[0-9a-fA-F]{130}$/.test(r.platform_signature)) {
    return { ok: false, error: 'BAD_SIGNATURE' }
  }
  const sig = Uint8Array.from(Buffer.from(r.platform_signature, 'hex'))
  if (sig.length !== 65) return { ok: false, error: 'BAD_SIGNATURE' }
  if (typeof expectedPlatformAddress !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(expectedPlatformAddress)) {
    return { ok: false, error: 'INVALID_FORMAT' }
  }
  const { intent_hash, display, user_id, wallet_address } = r
  const base = { v: 1 as const, action: r.action as SignedRequestAction, intent_hash, display, user_id, wallet_address, nonce: r.nonce, expires_at: r.expires_at }
  let recovered: `0x${string}`
  try {
    recovered = recoverSigner(canonicalBytes(base), sig)
  } catch {
    // P1-5: 不可信签名导致公钥恢复/验签异常 → 结构化 BAD_SIGNATURE（不抛到调用方）
    return { ok: false, error: 'BAD_SIGNATURE' }
  }
  if (recovered.toLowerCase() !== expectedPlatformAddress.toLowerCase()) {
    return { ok: false, error: 'BAD_SIGNATURE' }
  }
  return { ok: true, platformAddress: recovered }
}
