/**
 * 双闸门第二层：用户确认回调抽象
 *
 * MCP 薄壳 / CLI / 宿主应用注入各自的确认实现：
 * - CLI：终端确认（y/n）
 * - MCP：OS 弹窗（由宿主实现）
 * - 测试：自动放行/拒绝
 */
export interface ApprovalRequest {
  action: 'sign_message' | 'sign_tx' | 'bind_wallet' | 'withdraw_confirm' | 'wipe_wallet' | 'mnemonic_export' | 'restore_wallet'
  display: string
}

export type ApprovalHandler = (req: ApprovalRequest) => Promise<boolean> | boolean

/** 默认：仅允许低风险 action（sign_message 用于绑定/挑战），高风险一律拒绝
 * wipe_wallet 默认拒绝（W12）：MCP 路径的确认短语是代码硬编码常量、不经用户，
 * 不构成防线；不可逆高危操作必须由宿主注入 approval handler（如 OS 弹窗）显式
 * 放行。CLI 路径不经 approval，由用户手输 PERMANENT DELETE 确认，不受影响。
 */
export const defaultApproval: ApprovalHandler = (req) => {
  if (req.action === 'sign_message') return true
  return false
}
