/**
 * CLI 中英文（按系统语言自动切换）
 *
 * 检测顺序：SHARDNEST_LANG 显式覆盖 > LC_ALL / LC_MESSAGES / LANG 系统语言
 * 中文环境（zh*）→ 中文；其余 → 英文（默认）
 */
export type Lang = 'zh' | 'en'

export function detectLang(): Lang {
  const env = process.env.SHARDNEST_LANG || process.env.LC_ALL || process.env.LC_MESSAGES || process.env.LANG || ''
  return /^zh/i.test(env) ? 'zh' : 'en'
}

export const isZh = (): boolean => detectLang() === 'zh'

/** 双语文案选择 */
export function t(zh: string, en: string): string {
  return isZh() ? zh : en
}
