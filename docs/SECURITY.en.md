# Security Model

## Architecture Layers (Thin Shell Model)

```
MCP server (no keys) → local IPC → signing daemon (sole key holder)
```

- Compromising the MCP layer yields zero key material.
- Signing daemon: Keychain/Keystore protection + OS confirmation dialog + private key zeroed after use.

## Key Lifecycle

| Stage | Location | Protection |
|-------|----------|-----------|
| Generation | Client (CSPRNG) | Private key never derived from passphrase/identity factors |
| Sharding | SSS 2-of-3 | Single share carries zero information |
| Storage | Device Keychain + user cloud/recovery codes | Passphrase encrypts only the share (KEK), not the private key |
| Signing | In-memory recombination | Zeroed after use |
| Rotation | reshare | ⚠️ Old carriers must be physically destroyed (old share sets can still recombine the same key) |

## Threat Matrix

| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Service provider compromised | Zero key material | None |
| User device compromised | Keychain + dialogs | Cannot defend a fully compromised device (same as hardware wallets) |
| Prompt injection | Platform endorsement + user confirmation | User misclicks (re-passphrase for high-value ops) |
| Single share leaked | 2-of-3 threshold | Needs 2 shares leaked together |
| Mnemonic file leaked | Local-only 0600 file; single-point risk disclosed at generation | **Leak = total loss (no threshold protection)**; write it offline then run `wipe saved` |
| Mnemonic + recovery codes co-located | Separate custody responsibilities | Multiple independent leak surfaces; move mnemonic offline and wipe after generating |
| Passphrase + device both lost | — | Unrecoverable (disclosed at registration, reasonable boundary) |
| LLM context leaks passphrase/recovery codes | **Token sessions**: passphrase/recovery codes only entered locally in CLI; MCP receives 5-min single-use tokens (0600 encrypted files, consumed-once) | Token window = 5 min + single-use, still needs platform endorsement + user confirmation |
| Full local directory compromise (email delivered) | Local holds 1 encrypted share + 1 plaintext share | Cannot move funds (share ③ lives in the mailbox) |
| Full local directory compromise (no email) | Local holds 2 plaintext shares with prominent warning | Funds lost; move one share offline or configure email |

## Security Fix Records

### 2026-08-10 Expert Review Fixes (Crypto × Security dual lens)

| Level | Issue | Fix |
|-------|-------|-----|
| 🔴 P0 | MCP tool args exposed passphrase/recovery codes to the LLM | Token sessions (`unlock-session.ts`): CLI `unlock` enters credentials locally, token encrypted to disk (5-min TTL/0600/single-use); MCP `signed_request_sign` receives only `unlock_token`, deleted after use |
| 🟠 P1 | Recovery codes unvalidated → typo silently recovers a wrong wallet | Format `sn1-<index>-<hex>-<crc>` (keccak first byte); `restore` address cross-check (expectedAddress/old metadata) |
| 🟠 P1 | init/restore not atomic | init sends email before writing files; restore rolls back metadata on device-write failure |
| 🟠 P1 | Signing without wallet_address check | `signed_request_sign` enforces local address match → `WALLET_ADDRESS_MISMATCH` |
| 🟡 P2 | Weak passphrase / canonical delimiter ambiguity / silent bad key / echoed input | ≥12 chars enforced; canonicalString JSON serialization; `WalletVault` private key range check (0<priv<n); CLI masked input |

### 2026-08-10 Deep Review Fixes (3 perspectives: completeness × correctness × impact)

| Level | Issue | Fix |
|-------|-------|-----|
| 🔴 Critical | `wallet_restore` bypassed credential isolation: 2 recovery-code args + plaintext output all hit the LLM | Input via local file (`recovery_file_path`); output `recovery_codes_file`+`note`; min(12); new `expected_address`/`email` args + 2 functional tests |
| 🟠 Warning | `signMessage`/`createUnlockToken` left private keys in memory on exceptions | `vault.wipe()` moved into `finally`; privateKey null-init + finally zeroing |
| 🟠 Warning | init/restore recovery-code writes outside atomic/rollback scope | Writes moved first (no more permanent-lock state); meta/device/recovery three-file rollback |
| 🟠 Warning | Address cross-check ineffective on new-device recovery; email-update guidance not actionable | CLI/MCP expose `expected_address`; `restoreWallet` accepts email and auto-sends new share ③ |
| 🟡 Suggestion | CLI recovery-code echo / user_id·action unvalidated / raw 0x19 / schema 0x drift | Masked input; action whitelist + user_id check; `\x19` escape; schema drops 0x |
| 🔴 Passphrase token | `wallet_create`/`wallet_restore` passphrase arg still reached the LLM (last residual credential) | `passphrase_token` mechanism: CLI `passphrase-token` generates a passphrase session (0600/5-min/single-use); MCP tools receive only the token — **passphrases + recovery codes fully LLM-isolated** |

> Full suite 96/96 green at the time.

### 2026-08-10 Security Review Fixes (wipe / mnemonic / storage strategy A+B)

| Level | Issue | Fix |
|-------|-------|-----|
| 🔴 | `wipeWallet('all')` never cleaned the unlock dir (`getUnlockDir` not imported, error swallowed) | Import fixed; test proves unlock sessions removed |
| 🔴 | MCP restore path traversal (arbitrary file read + wallet replacement) | `assertSafePath`: paths must be inside the wallet dir + `realpath` symlink escape check |
| 🔴 | `wallet_mnemonic_export` extracted the full private key with no approval gate | Added `approval` gate (USER_REJECTED on denial) |
| 🔴 | `'wipe_wallet'` missing from `ApprovalRequest` union (tsc TS2322) | Type extended with `wipe_wallet`/`mnemonic_export` |
| 🟠 | Exception paths left plaintext private keys in memory | `finally` zeroing + atomic rollback |
| 🟠 | `secureDelete` silently skipped overwrite on EACCES + handle leak | try/finally close + warn + fresh random per position |
| 🟠 | `restoreFromMnemonic` missing old-carrier cleanup guidance | note extended (old codes/email share still valid — destroy) |
| 🟠 | Mnemonic file broke storage strategy A's three-location guarantee | SECURITY.md matrix rows added; init note advises offline transfer + `wipe saved` |
| 🟠 | `defaultApproval` rejected all wipes (dead tool) | `wipe_wallet` allowed by default (confirm phrase is the final gate) |
| 🟠 | Raw ENOENT after `wipe saved` on MCP export/restore | `NO_RECOVERY_FILE` with actionable CLI guidance |

> Full suite 97/97 green at the time.

## Dependency Audit Requirements

- All crypto primitives must come from audited, actively maintained libraries (`@noble/*`, `@scure/*`, `@modelcontextprotocol/sdk`).
- Any new dependency must be reviewed before merging; run `bun audit` periodically.
- No dependency may ever receive plaintext private keys (key material stays in-process only).
