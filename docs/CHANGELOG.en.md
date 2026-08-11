---
title: shardnest Changelog
date: 2026-08-09
status: active
last_reviewed: 2026-08-09
tags: ['changelog', 'release-notes', 'history']
---

# Changelog

> Grouped by milestone. Every commit is traceable via `git log --oneline`.

## v0.3.x — Crypto modernization (current)

### 2026-08-09 · Round-9 polish
- **I18**: `getAddress` validates metadata (corruption -> clean rejection instead of a bare TypeError)
- **I19**: empty `SHARDNEST_HOME` falls back to the default dir (wallet never lands in cwd)
- **I20**: random-source environment note; **I21**: MetaMask live check deferred until the first platform integration

### 2026-08-09 · Round-8 test hardening
- **W15**: BIP-44 standard address pin test (all-zero entropy mnemonic -> `0xF278cF59...`, dual-path cross-verified, MetaMask compatibility guard)
- **I17**: real v1 wallet (2^16-encrypted) decryption fixture (C1 regression guard)

### 2026-08-09 · Three-perspective review fixes
- **C1**: `decryptShare` v1 fallback uses the historical params (LEGACY 2^16) — real v1 wallets are never locked out
- **W2**: removed the dead `WalletVault.unlock(shares)` API (invalid semantics after O4A); tests rewritten
- **W3**: `createWalletFromEntropy` early-throw paths now zero entropy/shares (invariant 5, all paths)
- **W4**: recovery-code CRC dual-width compatibility (old 8-bit codes still accepted)
- **W5**: restore-mnemonic honestly warns about legacy-format mnemonic semantics
- **W6**: canonicalBytes layout comment fixed; **W7**: @scure/bip32 pinned exactly
- **W1**: stale docs fully synced (AGENTS/SECURITY/keys/shamir)

### 2026-08-09 · Optimization batch (O1-O6)
- **O1**: KDF params (scrypt N/r/p) persisted with ciphertext (device-share.json v2) — future upgrades never break old wallets
- **O2**: scrypt N 2^16 -> **2^17** (OWASP 2023 floor, 128MB)
- **O3**: recovery-code CRC 8 -> **32 bits** (miss rate 1/2^32)
- **O4A**: **BIP-39/44 standardization** (entropy as root: shares protect entropy -> m/44'/60'/0'/0/0 derived key) — mnemonic importable into MetaMask for the same address
- **O4B**: mnemonic guide copy updated (standard-compatible after O4A)
- **O5**: canonicalString(JSON) -> **canonicalBytes** (length-prefixed binary, cross-language safe)
- **W14**: BIP-39 seed included in invariant-5 memory zeroing; **S1**: docs synced

## v0.2.x — Security hardening

### 2026-08-09 · Nine-round review fixes (W1-W13)
- **C1**: init/restore failure rollback now also removes recovery/mnemonic files (full atomicity)
- **W1**: wipe confirm-prompt garbling fixed; **W2**: approval type union completed
- **W6-W8**: invariant-5 memory zeroing fully covered (shares/private key/seed)
- **W9**: init anti-silent-overwrite (force param + CLI confirm + MCP precheck)
- **W12**: default approval rejects wipe (secure-by-default)
- **W13**: canonical Unicode pitfall (fixed by O5)
- **I1**: tsc fixed (@types/bun); **I2-I10**: token copy / passphrase feedback / recovery-source guidance etc.

### 2026-08-09 · Feature enhancements
- Email backup share (init auto-sends share 3 when an email is provided)
- Optional 24-word mnemonic (default off, with pros/cons guidance)
- Export mnemonic from any 2 shares (mnemonic-export)
- wipe with two scopes (saved/all + file list + confirm phrase)
- CLI bilingual (auto-switch by system language; SHARDNEST_LANG override)
- Recovery-source guidance (second-factor source hints by storage policy)

## v0.1.x — Core capabilities

- M3 protocol layer: signed_request v1 (platform-endorsed issue/verify)
- MCP thin shell: 6 tools (wallet_create/address/mnemonic_export/signed_request_sign/restore/wipe)
- Credential isolation channels: passphrase_token / unlock_token / file paths
- Double gate: platform endorsement verification + approval confirmation
- SSS 2-of-3 sharding + EIP-191 signing + verify-sdk

---

## Release process

1. Run all tests: `for p in core signer cli verify-sdk protocol mcp-server; do (cd packages/$p && bun test); done`
2. Type check: `bunx tsc --noEmit` (must be 0 errors)
3. Update this file + SECURITY.md fix records
4. Commit & push to GitHub (shardnest is an independent repo with its own release cadence)
