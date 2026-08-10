/**
 * 备份分片邮件发送（SMTP，配置驱动）
 *
 * 用途：init 时用户提供邮箱 → 自动把 1 个备份分片（恢复码）发送到邮箱，
 * 作为「设备丢失 + 恢复码未保存」场景的最后备份通道。
 *
 * 安全：邮件中的恢复码只是 2-of-3 中的 1 片，单分片零信息量；
 * 邮箱被攻破 ≠ 私钥泄露（还需设备片或另一恢复码）。
 *
 * 配置（环境变量）：
 *   SHARDNEST_SMTP_HOST / SHARDNEST_SMTP_PORT / SHARDNEST_SMTP_USER /
 *   SHARDNEST_SMTP_PASS / SHARDNEST_SMTP_FROM / SHARDNEST_SMTP_TLS(可选)
 */
import nodemailer from 'nodemailer'

export interface SmtpConfig {
  host: string
  port: number
  user: string
  pass: string
  from: string
  tls: boolean
}

export function getSmtpConfig(): SmtpConfig | null {
  const host = process.env.SHARDNEST_SMTP_HOST
  if (!host) return null
  return {
    host,
    port: Number(process.env.SHARDNEST_SMTP_PORT ?? 465),
    user: process.env.SHARDNEST_SMTP_USER ?? '',
    pass: process.env.SHARDNEST_SMTP_PASS ?? '',
    from: process.env.SHARDNEST_SMTP_FROM ?? process.env.SHARDNEST_SMTP_USER ?? '',
    tls: (process.env.SHARDNEST_SMTP_TLS ?? 'true') !== 'false',
  }
}

export interface BackupMail {
  to: string
  address: string
  recoveryCode: string
  subject: string
  body: string
}

/** 构造备份分片邮件内容 */
export function buildBackupMail(to: string, address: string, recoveryCode: string): BackupMail {
  return {
    to,
    address,
    recoveryCode,
    subject: '[shardnest] 钱包备份分片（请妥善保存）',
    body: [
      `钱包地址: ${address}`,
      '',
      '这是您的钱包备份分片（2-of-3 中的 1 片）：',
      recoveryCode,
      '',
      '使用说明：',
      '- 本分片 + 设备分片（口令解锁）可恢复钱包',
      '- 或 本分片 + 另一恢复码 可恢复钱包',
      '- 单凭本分片无法动用资金（需 2 片）',
      '- 请勿在聊天/社交软件中转发本邮件',
      '',
      'shardnest — 自托管钱包服务',
    ].join('\n'),
  }
}

/**
 * 发送备份分片到邮箱。
 * @returns 'sent' | 'skipped'（未配置 SMTP）
 * @throws 配置了 SMTP 但发送失败（用户需要知道备份未送达）
 */
export async function sendBackupShare(
  to: string,
  address: string,
  recoveryCode: string,
  config: SmtpConfig | null = getSmtpConfig(),
): Promise<'sent' | 'skipped'> {
  if (!config) return 'skipped'
  const mail = buildBackupMail(to, address, recoveryCode)
  const transporter = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.tls,
    auth: config.user ? { user: config.user, pass: config.pass } : undefined,
  })
  await transporter.sendMail({
    from: config.from,
    to: mail.to,
    subject: mail.subject,
    text: mail.body,
  })
  return 'sent'
}
