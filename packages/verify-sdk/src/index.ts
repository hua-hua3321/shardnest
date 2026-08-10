/**
 * 平台侧验签 SDK（M3 实现）——verify-only，无任何密钥逻辑
 *
 * 用途：平台验证用户钱包返回的签名（提现确认、绑定钱包等）
 */
export function verifySignature(): never {
  throw new Error('M3: verifySignature 待实现（基于 noble-curves）')
}
