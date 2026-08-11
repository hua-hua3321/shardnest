/**
 * BIP-39 助记词（可选备份通道，默认关闭）
 *
 * 语义：助记词 = 完整私钥的备份（与 2-of-3 分片体系并存、独立）。
 * - 24 词：承载 256 位熵 = 32 字节私钥（12 词仅 128 位，无法承载完整私钥，
 *   故不支持——密码学容量约束，非产品取舍）
 * - 单凭 24 词即可恢复钱包（绕过门限）；但这是**单点**：泄露即资金丢失，
 *   与「分片单份零信息量」的安全保证不同——生成时必须向用户披露
 *
 * 用法：
 *   privateKeyToMnemonic(priv)      → 24 词
 *   mnemonicToPrivateKey(words)     → 私钥（校验和校验，篡改/抄错即拒绝）
 */
import { wordlist } from '@scure/bip39/wordlists/english'
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39'

/** 私钥 → 24 词助记词（BIP-39 标准：256 位熵 + 8 位校验） */
export function privateKeyToMnemonic(privateKey: Uint8Array): string {
  if (privateKey.length !== 32) throw new Error('助记词仅支持 32 字节（256 位）私钥')
  return entropyToMnemonic(privateKey, wordlist)
}

/**
 * 24 词助记词 → 私钥
 * @throws 词数/词表/校验和不符（抄错、篡改即拒绝）
 */
export function mnemonicToPrivateKey(mnemonic: string): Uint8Array {
  const normalized = mnemonic.trim().toLowerCase().split(/\s+/).join(' ')
  if (!validateMnemonic(normalized, wordlist)) {
    throw new Error('助记词无效（词数/词表/校验和错误），请核对后重试')
  }
  return new Uint8Array(mnemonicToEntropy(normalized, wordlist))
}

/** 助记词格式预校验（长度与基本形态，供 UI 早失败） */
export function isLikelyMnemonic(input: string): boolean {
  const words = input.trim().split(/\s+/)
  return words.length === 24 && words.every((w) => wordlist.includes(w.toLowerCase()))
}
