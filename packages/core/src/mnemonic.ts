/**
 * BIP-39/44 标准化助记词（O4A：熵为根）
 *
 * 钱包根 = 32 字节熵（CSPRNG）→ BIP-39 24 词（可逆编码）→ seed(PBKDF2-2048)
 * → BIP-32 HDKey → m/44'/60'/0'/0/0 派生账户私钥（单向）。
 *
 * 与旧版（私钥直接作熵）的区别：分片对象是**熵**而非私钥——
 * 任意 2 片恢复码重组熵后既可派生私钥（签名），也可导出助记词（备份），
 * 且 24 词可导入 MetaMask 等标准钱包得到同一地址。
 */
import { entropyToMnemonic as b39EntropyToMnemonic, mnemonicToEntropy as b39MnemonicToEntropy, mnemonicToSeedSync } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english'
import { HDKey } from '@scure/bip32'

/** 派生路径：EVM 标准账户路径 */
export const BIP44_PATH = "m/44'/60'/0'/0/0"

/** 熵 → BIP-39 24 词（标准可逆编码；@scure/bip39 保证校验和） */
export function entropyToMnemonic(entropy: Uint8Array): string {
  if (entropy.length !== 32) throw new Error('熵必须为 32 字节（256 位）')
  return b39EntropyToMnemonic(entropy, wordlist)
}

/** 24 词 → 熵（校验和校验，篡改/抄错即拒绝；12 词 128 位容量不足会报错） */
export function mnemonicToEntropy(mnemonic: string): Uint8Array {
  try {
    return b39MnemonicToEntropy(mnemonic.trim(), wordlist)
  } catch {
    throw new Error('助记词无效（校验和错误或词表不符）——请核对后重试')
  }
}

/** 助记词 → seed（BIP-39 PBKDF2-HMAC-SHA512 2048 轮） */
export function mnemonicToSeed(mnemonic: string): Uint8Array {
  return mnemonicToSeedSync(mnemonic.trim(), '')
}

/** seed → BIP-32 账户私钥（m/44'/60'/0'/0/0） */
export function derivePrivateKeyFromSeed(seed: Uint8Array): Uint8Array {
  const hd = HDKey.fromMasterSeed(seed)
  const child = hd.derive(BIP44_PATH)
  if (!child.privateKey) throw new Error('BIP-32 派生失败（无私钥）')
  return child.privateKey
}

/** 助记词 → 账户私钥（全链派生） */
export function derivePrivateKeyFromMnemonic(mnemonic: string): Uint8Array {
  const seed = mnemonicToSeed(mnemonic) // 64B seed = 钱包根访问权（可派生所有子私钥）
  try {
    return derivePrivateKeyFromSeed(seed)
  } finally {
    seed.fill(0) // 不变式 5：seed 敏感度等同私钥，任何路径均清零
  }
}

/** 熵 → 账户私钥（init/签名共用入口） */
export function derivePrivateKeyFromEntropy(entropy: Uint8Array): Uint8Array {
  return derivePrivateKeyFromMnemonic(entropyToMnemonic(entropy))
}

/** 粗略判断是否为 BIP-39 助记词（长度 + 词表校验和） */
export function isLikelyMnemonic(mnemonic: string): boolean {
  const words = mnemonic.trim().split(/\s+/)
  if (words.length !== 24) return false
  try {
    b39MnemonicToEntropy(words.join(' '), wordlist)
    return true
  } catch {
    return false
  }
}
