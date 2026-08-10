/**
 * MCP 薄壳（M3 实现）
 *
 * 职责（无密钥）：
 * - 暴露 MCP 工具：wallet_create / signed_request_sign / wallet_restore / wallet_reshare
 * - 验平台背书 → 转发签名守护进程 → 返回结果
 *
 * 安全：本层被攻破 = 拿不到任何密钥（薄壳架构）。
 */
export const MCP_TOOLS = ['wallet_create', 'signed_request_sign', 'wallet_restore', 'wallet_reshare'] as const
