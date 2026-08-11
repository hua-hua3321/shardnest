export { WalletVault } from './vault'
export { createUnlockSession, consumeUnlockSession, createPassphraseSession, consumePassphraseSession, UNLOCK_TTL_MS, getUnlockDir, type SessionType } from './unlock-session'
export { defaultApproval, type ApprovalHandler, type ApprovalRequest } from './approval'
export type { Share } from '@wallet-service/core'

export { cleanupExpiredUnlockSessions } from './unlock-session'
