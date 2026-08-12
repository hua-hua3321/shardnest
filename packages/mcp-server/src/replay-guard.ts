/**
 * 钱包侧重放防护（P1-3）：短期已用 nonce 缓存，补平台侧一次性消费的兜底。
 *
 * 背景：signed_request 的防重放完全依赖平台对 nonce 的一次性原子消费。
 * 钱包本身无状态——若平台因 bug 或被攻破，在有效期内复用同一 nonce，
 * `verifySignedRequest` 仅校验时效（expires_at），无法识别"已被签过"的请求。
 *
 * 本守护在钱包侧记录「已成功验签的 nonce」，在消费解锁令牌前拦截重放，
 * 即使平台失效也能避免同一请求被重复签名。
 *
 * 设计要点：
 * - key = `${platformAddress.toLowerCase()}:${nonce}`，按平台隔离。
 * - 过期条目（expires_at ≤ now）在每次检查时惰性清理——过期后 verifySignedRequest
 *   已以 EXPIRED 拒绝，此处仅释放内存。
 * - 容量上限保护内存；正常本地钱包请求量极低，几乎不会触及。
 */
export class ReplayGuard {
  private readonly seen = new Map<string, number>() // key -> expiresAtMs
  private readonly capacity: number

  constructor(capacity = 100_000) {
    this.capacity = capacity
  }

  /**
   * 记录并检查 nonce 是否已用。
   * @param key 平台地址+nonce 复合键
   * @param expiresAtMs 请求过期时间（ms），用于过期清理
   * @param nowMs 当前时间（ms），可注入便于测试
   * @returns true 表示重放（该 nonce 在有效期内已被用过）
   */
  isReplay(key: string, expiresAtMs: number, nowMs: number = Date.now()): boolean {
    // 惰性清理过期条目
    for (const [k, exp] of this.seen) {
      if (exp <= nowMs) this.seen.delete(k)
    }
    if (this.seen.has(key)) return true
    this.seen.set(key, expiresAtMs)
    // 容量兜底：超上限时丢弃最早插入的条目
    if (this.seen.size > this.capacity) {
      const oldest = this.seen.keys().next().value
      if (oldest !== undefined) this.seen.delete(oldest)
    }
    return false
  }

  /** 测试/运维用：清空缓存 */
  clear(): void {
    this.seen.clear()
  }
}
