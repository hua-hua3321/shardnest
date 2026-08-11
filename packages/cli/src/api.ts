/**
 * CLI 库 API（供 MCP 薄壳等程序化调用；CLI 入口在 index.ts）
 */
export {
  getHomeDir,
  initWallet,
  getAddress,
  signMessage,
  restoreWallet,
  encodeRecoveryCode,
  decodeRecoveryCode,
  createUnlockToken,
  validatePassphrase,
  readRecoveryCodesFromFile,
  restoreFromMnemonic,
  exportMnemonic,
  exportMnemonicFromCodes,
  wipeWallet,
  WIPE_CONFIRM_PHRASE,
  type InitResult,
} from './commands'
