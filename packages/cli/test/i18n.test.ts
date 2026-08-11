import { describe, it, expect, beforeEach } from 'bun:test'
import { detectLang, isZh, t } from '../src/i18n'

const OLD_ENV = process.env

beforeEach(() => {
  process.env = { ...OLD_ENV }
  delete process.env.SHARDNEST_LANG
  delete process.env.LC_ALL
  delete process.env.LC_MESSAGES
  delete process.env.LANG
})

describe('i18n 语言检测', () => {
  it('SHARDNEST_LANG=zh → 中文', () => {
    process.env.SHARDNEST_LANG = 'zh'
    expect(detectLang()).toBe('zh')
    expect(isZh()).toBe(true)
    expect(t('中文', 'English')).toBe('中文')
  })

  it('SHARDNEST_LANG=en → 英文（显式覆盖优先）', () => {
    process.env.SHARDNEST_LANG = 'en'
    process.env.LANG = 'zh_CN.UTF-8'
    expect(detectLang()).toBe('en')
    expect(t('中文', 'English')).toBe('English')
  })

  it('LANG=zh_CN.UTF-8 → 中文（系统语言）', () => {
    process.env.LANG = 'zh_CN.UTF-8'
    expect(detectLang()).toBe('zh')
  })

  it('LANG=en_US.UTF-8 → 英文（默认）', () => {
    process.env.LANG = 'en_US.UTF-8'
    expect(detectLang()).toBe('en')
  })

  it('未设置任何语言变量 → 英文（默认）', () => {
    expect(detectLang()).toBe('en')
  })
})
