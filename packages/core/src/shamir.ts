/**
 * Shamir Secret Sharing over GF(2^8)
 *
 * - 域：GF(2^8)，模多项式 0x11b（与 AES S-box 相同）
 * - 秘密按字节拆分，每个字节对应一个固定多项式（次数 = threshold-1，
 *   常数项 = 该字节）；所有分片对同一组多项式在不同 x 处求值
 * - 分片格式：[index(1B)] + [share bytes(len = 秘密长度)]
 * - 任意 threshold 个分片可重组出原秘密；少于 threshold 个在数学上零信息量
 *
 * 参考：Adi Shamir, "How to Share a Secret" (1979)
 */

const GF_MOD = 0x11b

/** GF(2^8) 乘法（指数/对数查表）
 * ⚠️ 生成元必须是 3（0x03）：AES 域中元素 2 的乘法阶仅为 51（非本原元），
 * 用 2 建表会漏掉大量元素；3 是阶 255 的本原元。
 */
const EXP = new Uint8Array(512)
const LOG = new Uint8Array(256)
;(() => {
  // x *= 3（GF 下）：x*3 = (x<<1) ^ x，高位溢出时 ^0x11b 规约
  const mul3 = (v: number): number => {
    let t = v << 1
    if (t & 0x100) t ^= GF_MOD
    return t ^ v
  }
  let x = 1
  for (let i = 0; i < 255; i++) {
    EXP[i] = x
    LOG[x] = i
    x = mul3(x)
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]
})()

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0
  return EXP[LOG[a] + LOG[b]]
}

/** 拉格朗日插值：给定点集 (xs, ys)，求多项式在 x 处的值 */
function lagrangeInterpolate(xs: number[], ys: number[], x: number): number {
  let result = 0
  for (let i = 0; i < xs.length; i++) {
    let num = 1
    let den = 1
    for (let j = 0; j < xs.length; j++) {
      if (i === j) continue
      num = gfMul(num, x ^ xs[j])
      den = gfMul(den, xs[i] ^ xs[j])
    }
    // 域内除法 = 乘逆元（小域上枚举求逆）
    let inv = 0
    for (let k = 0; k < 256; k++) {
      if (gfMul(den, k) === 1) {
        inv = k
        break
      }
    }
    result ^= gfMul(ys[i], gfMul(num, inv))
  }
  return result
}

/** 随机多项式系数（次数 = degree，常数项 = secretByte） */
function randomCoefficients(secretByte: number, degree: number, rng: () => number): number[] {
  const coeffs = [secretByte]
  for (let i = 1; i <= degree; i++) {
    coeffs.push(rng() & 0xff)
  }
  return coeffs
}

function evaluatePolynomial(coeffs: number[], x: number): number {
  // Horner
  let acc = 0
  for (let i = coeffs.length - 1; i >= 0; i--) {
    acc = gfMul(acc, x) ^ coeffs[i]
  }
  return acc
}

export interface Share {
  /** 分片索引（1-based，作为多项式的 x 坐标） */
  index: number
  /** 分片字节（长度 = 秘密长度） */
  bytes: Uint8Array
}

export interface SplitOptions {
  /** 分片总数 n */
  shares: number
  /** 恢复阈值 t */
  threshold: number
  /** 随机源（默认 crypto.getRandomValues），可注入用于测试 */
  rng?: () => number
}

/** 默认密码学安全随机源 */
function defaultRng(): () => number {
  const buf = new Uint8Array(1)
  return () => {
    crypto.getRandomValues(buf)
    return buf[0]
  }
}

/**
 * 将秘密拆分为 n 份，任意 threshold 份可重组。
 * 每个字节生成一个固定多项式，分片 = 各多项式在不同 x 处的求值结果。
 */
export function splitSecret(secret: Uint8Array, options: SplitOptions): Share[] {
  const { shares, threshold, rng = defaultRng() } = options
  if (shares < 2) throw new Error('shares must be >= 2')
  if (threshold < 2 || threshold > shares) {
    throw new Error('threshold must be in [2, shares]')
  }
  if (secret.length === 0) throw new Error('secret must not be empty')

  // 1. 每个字节一个固定多项式
  const polys: number[][] = []
  for (let i = 0; i < secret.length; i++) {
    polys.push(randomCoefficients(secret[i], threshold - 1, rng))
  }

  // 2. 每个分片 = 同一组多项式在 x 处的求值
  const result: Share[] = []
  for (let x = 1; x <= shares; x++) {
    const bytes = new Uint8Array(secret.length)
    for (let i = 0; i < secret.length; i++) {
      bytes[i] = evaluatePolynomial(polys[i], x)
    }
    result.push({ index: x, bytes })
  }
  return result
}

/**
 * 从任意 threshold 个分片重组秘密（少于 threshold 无法重组）。
 * 注意：传入超过 threshold 个分片时全部参与插值（诚实分片结果一致；
 * 若混入错误分片将静默产出垃圾值——调用方应做地址/校验和交叉验证）。
 */
export function combineShares(parts: Share[]): Uint8Array {
  if (parts.length < 2) throw new Error('need at least 2 shares')
  const len = parts[0].bytes.length
  for (const p of parts) {
    if (p.bytes.length !== len) throw new Error('share length mismatch')
  }
  // 校验 x 坐标唯一
  const xs = parts.map((p) => p.index)
  if (new Set(xs).size !== xs.length) throw new Error('duplicate share index')

  const secret = new Uint8Array(len)
  for (let i = 0; i < len; i++) {
    secret[i] = lagrangeInterpolate(xs, parts.map((p) => p.bytes[i]), 0)
  }
  return secret
}

/**
 * Reshare：用任意 threshold 个分片重组秘密后，重新生成整套分片。
 * ⚠️ 注意：旧分片在密码学上仍然有效（同一秘密可被旧多项式族重组），
 * 因此 reshare 必须配合「旧载体物理清理」（旧设备清除/旧邮件删除/旧备份作废）。
 */
export function reshareShares(parts: Share[], options: { shares: number; threshold: number; rng?: () => number }): Share[] {
  const secret = combineShares(parts) // 组合出的 secret = 明文私钥
  try {
    return splitSecret(secret, options)
  } finally {
    secret.fill(0) // 不变式 5：中间私钥任何路径均清零
  }
}
