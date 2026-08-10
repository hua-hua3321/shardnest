import { describe, it, expect, beforeEach } from 'bun:test'
import { buildBackupMail, getSmtpConfig, sendBackupShare } from '../src/mailer'

const OLD_ENV = process.env

beforeEach(() => {
  process.env = { ...OLD_ENV }
  delete process.env.SHARDNEST_SMTP_HOST
  delete process.env.SHARDNEST_SMTP_USER
  delete process.env.SHARDNEST_SMTP_PASS
  delete process.env.SHARDNEST_SMTP_FROM
})

describe('mailer', () => {
  it('buildBackupMail：含地址、恢复码、安全提示', () => {
    const mail = buildBackupMail('user@example.com', '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf', 'sn1-3-abcdef')
    expect(mail.to).toBe('user@example.com')
    expect(mail.body).toContain('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')
    expect(mail.body).toContain('sn1-3-abcdef')
    expect(mail.body).toContain('单凭本分片无法动用资金')
    expect(mail.body).toContain('请勿在聊天/社交软件中转发')
  })

  it('getSmtpConfig：未配置 → null', () => {
    expect(getSmtpConfig()).toBeNull()
  })

  it('getSmtpConfig：配置解析（默认端口 465 + TLS）', () => {
    process.env.SHARDNEST_SMTP_HOST = 'smtp.example.com'
    process.env.SHARDNEST_SMTP_USER = 'no-reply@example.com'
    process.env.SHARDNEST_SMTP_PASS = 'secret'
    const cfg = getSmtpConfig()!
    expect(cfg.host).toBe('smtp.example.com')
    expect(cfg.port).toBe(465)
    expect(cfg.from).toBe('no-reply@example.com')
    expect(cfg.tls).toBe(true)
  })

  it('sendBackupShare：未配置 SMTP → skipped（不抛错）', async () => {
    expect(await sendBackupShare('a@b.com', '0x1', 'sn1-3-00', null)).toBe('skipped')
  })
})
