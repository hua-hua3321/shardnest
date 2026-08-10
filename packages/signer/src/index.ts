/**
 * 签名守护进程（M2 实现）
 *
 * 职责（唯一持钥者）：
 * - 持有/解锁分片（Keychain/Keystore）
 * - 验证平台背书（signed_request 验签）
 * - OS 弹窗用户确认
 * - 本地签名，用完清零
 *
 * 安全边界：本进程是唯一能接触私钥的组件；MCP 薄壳无密钥。
 */
export const SIGNER_IPC = {
  /** 本地 IPC 通道（Unix socket / 随机端口 + token），M2 定义 */
  protocol: 'unix-socket',
} as const
