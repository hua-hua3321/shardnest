/**
 * 双闸门第二层：用户确认回调抽象
 *
 * MCP 薄壳 / CLI / 宿主应用注入各自的确认实现：
 * - CLI：终端确认（y/n）
 * - MCP：OS 弹窗（由宿主实现）
 * - 测试：自动放行/拒绝
 */
export interface ApprovalRequest {
  action: 'sign_message' | 'sign_tx' | 'bind_wallet' | 'withdraw_confirm'
  display: string
}

export type ApprovalHandler = (req: ApprovalRequest) => Promise<boolean> | boolean

/** 默认：仅允许低风险 action（sign_message 用于绑定/挑战），高风险一律拒绝 */
export const defaultApproval: ApprovalHandler = (req) => {
  if (req.action === 'sign_message') return true
  // wipe 已由确认短语（PERMANENT DELETE）作最终防线，默认放行以便功能可用
  if (req.action === 'wipe_wallet') return true
  return false
}
