import { describe, it, expect } from 'bun:test'
import { splitSecret, combineShares, reshareShares, type Share } from '../src/shamir'

/** 确定性伪随机（LGC）——保证测试可复现，注入给 splitSecret */
function makeRng(seed = 42) {
  let s = seed
  return () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff
    return (s >>> 16) & 0xff
  }
}

const SECRET = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xff, 0xee, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0])

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

describe('Shamir SSS 2-of-3', () => {
  const shares = splitSecret(SECRET, { shares: 3, threshold: 2, rng: makeRng(1) })

  it('拆出 3 片，每片长度 = 秘密长度', () => {
    expect(shares.length).toBe(3)
    for (const s of shares) expect(s.bytes.length).toBe(SECRET.length)
  })

  it('任意两片可重组原秘密（全部组合）', () => {
    const combos = [
      [0, 1], [0, 2], [1, 2],
    ]
    for (const [i, j] of combos) {
      const recovered = combineShares([shares[i], shares[j]])
      expect(eq(recovered, SECRET)).toBe(true)
    }
  })

  it('单片无法重组（抛错）', () => {
    expect(() => combineShares([shares[0]])).toThrow()
  })
})

describe('Shamir SSS 3-of-5', () => {
  const shares = splitSecret(SECRET, { shares: 5, threshold: 3, rng: makeRng(2) })

  it('任意三片可重组（抽查 5 组组合）', () => {
    const combos = [
      [0, 1, 2], [0, 2, 4], [1, 3, 4], [2, 3, 4], [0, 1, 4],
    ]
    for (const idx of combos) {
      const recovered = combineShares(idx.map((i) => shares[i]))
      expect(eq(recovered, SECRET)).toBe(true)
    }
  })

  it('两片不够（结果不等于原秘密）', () => {
    // 2 片时插值出错误结果（多项式次数不足，必不等于原秘密——高概率）
    const recovered = combineShares([shares[0], shares[1]])
    expect(eq(recovered, SECRET)).toBe(false)
  })
})

describe('reshare 语义', () => {
  it('reshare 后新分片集重组出同一秘密', () => {
    const old = splitSecret(SECRET, { shares: 3, threshold: 2, rng: makeRng(3) })
    const fresh = reshareShares([old[0], old[1]], { shares: 3, threshold: 2, rng: makeRng(4) })
    const recovered = combineShares([fresh[0], fresh[2]])
    expect(eq(recovered, SECRET)).toBe(true)
  })

  it('⚠️ 旧分片之间仍能重组同一秘密——reshare 不是密码学作废，必须物理清理旧载体', () => {
    const old = splitSecret(SECRET, { shares: 3, threshold: 2, rng: makeRng(5) })
    const fresh = reshareShares([old[0], old[1]], { shares: 3, threshold: 2, rng: makeRng(6) })
    // 旧分片集内部任意 2 片仍可重组 S（攻击者拿到旧片仍可恢复私钥）
    const recovered = combineShares([old[1], old[2]])
    expect(eq(recovered, SECRET)).toBe(true)
    // 旧片 + 新片混用无法重组（不同多项式族不兼容）——所以「换片」必须整体重分
    const mixed = combineShares([old[0], fresh[1]])
    expect(eq(mixed, SECRET)).toBe(false)
  })
})

describe('边界校验', () => {
  it('分片索引重复 → 抛错', () => {
    const shares = splitSecret(SECRET, { shares: 3, threshold: 2, rng: makeRng(7) })
    const dup = [{ ...shares[0], index: shares[1].index }, shares[1]]
    expect(() => combineShares(dup)).toThrow(/duplicate share index/)
  })

  it('分片长度不匹配 → 抛错', () => {
    const shares = splitSecret(SECRET, { shares: 3, threshold: 2, rng: makeRng(8) })
    const bad = [{ ...shares[0], bytes: new Uint8Array([1, 2, 3]) }, shares[1]]
    expect(() => combineShares(bad)).toThrow(/length mismatch/)
  })

  it('非法阈值 → 抛错', () => {
    expect(() => splitSecret(SECRET, { shares: 3, threshold: 1 })).toThrow()
    expect(() => splitSecret(SECRET, { shares: 3, threshold: 4 })).toThrow()
  })

  it('空秘密 → 抛错', () => {
    expect(() => splitSecret(new Uint8Array(0), { shares: 3, threshold: 2 })).toThrow()
  })
})
