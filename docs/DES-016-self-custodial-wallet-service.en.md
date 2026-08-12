---
title: 独立开源钱包服务项目规划（DES-016）English
date: 2026-08-10
status: active
last_reviewed: 2026-08-10
tags: ['wallet', 'open-source', 'independent-project', 'MCP', 'SSS', 'self-custodial', 'verification-protocol']
---

# Independent Open-Source Wallet Service — Plan (DES-016)

> **Nature:** Independent project plan (draft). This is an **independent open-source project**:
> separate repository, separate release cadence, separate governance — loosely coupled to any business platform only via the public `signed_request` protocol.

## 1. Positioning

**One-liner:** Open-source, self-hosted, non-custodial wallet infrastructure — key generation, Shamir secret sharing, recovery, and signature verification, delivered as MCP server / CLI / SDK. Any platform that follows the public protocol can integrate.

| Dimension | Positioning |
|-----------|-------------|
| Niche | Comparable to Web3Auth / Lit Protocol, differentiated by: **open source + user-local self-hosting + generic endorsement protocol** |
| Responsibility model | 100% of wallet/key custody responsibility belongs to the user (self-custody); the service holds zero key material |
| Delivery forms | MCP server (primary channel for the Agent ecosystem) + CLI (human scenarios) + SDK (platform integration) |
| Open-source strategy | Independent repository (MIT/Apache-2.0), limited release first, then fully open |

## 2. Why Independent (Decision Background)

1. **Clean responsibility separation**: wallet responsibility belongs to the user; business platforms hold zero key material — the cleanest "non-custodial" compliance stance.
2. **Generic infrastructure**: any platform (task matching, e-commerce, social) can integrate, reusing the same wallet service.
3. **Ecosystem reuse**: open-source = auditable, evolvable, community-building (the Phantom MCP / Coinbase Payments MCP niche, but insisting on self-hosting).
4. **Platform agnosticism**: no interference, independent releases, independent license; any platform connects via the protocol.

## 3. Core Capabilities

| Capability | Description |
|-----------|-------------|
| Wallet generation | CSPRNG random private key (passphrase never participates in the key, only encrypts it) |
| Key sharding | Shamir SSS 2-of-3 (any 2 shares recombine) |
| Share storage | Share ① device (passphrase-encrypted); share ② recovery code (local); share ③ **email backup** (auto-sent at init when an email is provided; falls back to codes/paper) |
| Email backup | User provides email at init → share ③ sent automatically (SMTP config driven); single share carries zero information; mailbox compromise ≠ key leak |
| Signing | Verify platform endorsement → user confirmation → local signing (double gate) |
| Recovery | Passphrase lost / device lost / share recombination (client-side) |
| Mnemonic (optional, off by default) | 24-word BIP-39 backup = full private key (single point); generated on init or exported from any 2 shares; standalone recovery |
| reshare | Full re-split + physical cleanup of old carriers (two-phase) |
| Verify SDK | Platform-side integration (`recoverSigner`, verify-only) |
| Wipe | Two scopes: `saved` (plaintext backups only, wallet stays usable) / `all` (everything); 3× random overwrite + delete; confirm phrase `PERMANENT DELETE` |

### 3.7 Email Backup Share (auto-sent at init)

> Creating a wallet with an email → **share ③ (backup share)** is sent to the mailbox automatically, as the last-resort channel for "device lost + recovery codes not saved".

**Config (environment variables, SMTP-driven):**

| Variable | Meaning |
|----------|---------|
| `SHARDNEST_SMTP_HOST` | SMTP server (required to enable sending) |
| `SHARDNEST_SMTP_PORT` | Port (default 465) |
| `SHARDNEST_SMTP_USER` / `SHARDNEST_SMTP_PASS` | Credentials |
| `SHARDNEST_SMTP_FROM` | Sender (defaults to USER) |
| `SHARDNEST_SMTP_TLS` | TLS (default true) |

**Three states:**

| Scenario | Behavior |
|----------|----------|
| Email provided + SMTP configured + sent | `backupStatus: sent` ✅ — local `recovery-codes.txt` holds only share ② (true three-location distribution) |
| Email provided + SMTP not configured | `skipped` — both shares stay local with a prominent warning |
| SMTP configured but send fails | **Abort with error** (user must know the backup did not arrive) |

**Security design:**

- Email carries only **1 share (③)** — 2-of-3 single share carries zero information; mailbox compromise ≠ key leak (still needs the device share or another code).
- Recovery paths: **email share + device share (passphrase)** or **email share + another recovery code**.
- Providing an email means the send must complete (format failure/send failure abort creation) — no "thought I backed it up" traps.

## 4. Architecture Design

### 4.1 Thin-shell MCP + Signing Daemon (anti-abuse)

> ⚠️ **Roadmap (P0-3), not yet implemented**: current build is a single process —
> the MCP server consumes unlock sessions and instantiates `WalletVault` in-process.
> The security promise today is "credentials never enter LLM", not "keyless MCP".

```
┌─ MCP server (keyless thin shell) [roadmap] ──┐
│ verify endorsement → forward → return result   │  (compromisable, yields no keys)
└────────────────────┬───────────────────────────┘
                     │ local IPC
┌────────────────────▼───────────────────────────┐
│ Signing daemon (sole key holder)                │
│ recompose shares in memory → sign → wipe        │
│ OS confirmation dialog (double gate)            │
└─────────────────────────────────────────────────┘
```

### 4.2 Credential Isolation (core security invariant)

**Passphrases and recovery codes never enter an LLM context.** Three channels:

| Credential | Channel | Mechanism |
|-----------|---------|-----------|
| Passphrase | `passphrase_token` | CLI `passphrase-token` enters locally → encrypted session file (0600/5-min/single-use) → MCP consumes |
| Recovery code (input) | `recovery_file_path` | Only the local file path crosses the LLM; content read by the MCP process |
| Recovery code (output) | `recovery_codes_file` | MCP responses contain only the file path + email status |

**Rule:** any new MCP tool must route sensitive credentials through token/file-path channels; CLI inputs must use masked prompts.

### 4.3 Storage Layout (`~/.shardnest/`, `SHARDNEST_HOME` overrides; tests use isolated dirs)

```
metadata.json        plaintext { address } (address is not secret)
device-share.json    share ①, passphrase-encrypted (scrypt KEK + AES-GCM, 0600)
recovery-codes.txt   share ② (+③ only when email not delivered) plaintext codes (0600)
mnemonic.txt         (optional) 24-word mnemonic = full private key backup (single point, 0600)
unlock/              token sessions: unlock-*.bin / passphrase-*.bin / consuming-*.bin
```

## 5. Public Protocol: signed_request v1 (the only coupling point with platforms)

```
Platform (endorser)                         Wallet service (signer)
──────────────────                          ──────────────────────
issueSignedRequest(                         verifySignedRequest(
  action, intent_hash, display,               request, expected_platform_address
  user_id, wallet_address, nonce,           → endorsement + nonce/expiry/field checks
  expires_at, platform_signature)          → user confirmation (approval)
                                            → EIP-191 signature on domain-separated request context
                                              (wallet_address | platform_address | action | intent_hash
                                              | nonce | expires_at | user_id, via protocol.walletSignMessage)
                                            → platform verifies via verify-sdk
```

- `canonicalBytes`: length-prefixed deterministic binary (v 1B | action lp | intent_hash 32B | display lp | user_id lp | wallet_address 20B | nonce lp | expires_at 8B BE) — UTF-8 bytes + 4-byte BE length prefixes; no JSON/Unicode/int-float ambiguity across languages.
- EIP-191 hashing must stay byte-identical across `vault.ts` / `verify-sdk` / `protocol` (three implementations).
- Fields validated: `action` whitelist, `intent_hash`/`wallet_address` format, `display` length, `expires_at` integer, `user_id` non-empty.
- Recovery-bit convention: 0/1 (65-byte `r||s||v`, no `0x` prefix).

## 6. Technology Choices (all mature, reused components)

| Component | Choice |
|-----------|--------|
| Crypto primitives | `@noble/curves`, `@noble/hashes`, `@noble/ciphers`, `@scure/bip39` |
| Shamir SSS | In-house over GF(2^8) (generator must be 3; 0x11b modulus) |
| Protocol/MCP | `@modelcontextprotocol/sdk` |
| Runtime | Bun + TypeScript workspace |
| Local storage | Keychain / Android Keystore / WebCrypto (IndexedDB) — system-level protection |
| Release | npm package + GitHub Release + GPG signing — supply-chain protection |

## 7. Independent Repository Layout (plan)

```
wallet-service/                    ← independent git repo (no code shared with any business platform)
├── packages/
│   ├── core/                      # key generation, SSS split/recover/reshare (pure logic, no IO)
│   ├── signer/                    # signing daemon (key holder, dialogs, token sessions)
│   ├── mcp-server/                # MCP thin shell (no keys) [roadmap P0-3; current: same-process, credentials never enter LLM]
│   ├── cli/                       # CLI form (human scenarios; i18n zh/en by system language)
│   └── verify-sdk/                # platform-side verify SDK (verify-only, no key logic)
├── protocol/                      # signed_request v1 spec (JSON Schema + docs)
├── tests/                         # vector tests, share recovery, concurrency, attack scenarios
├── docs/                          # security model, integration guide, audit reports (zh + en)
└── LICENSE / README.md (zh + en)
```

## 8. Security Model & Boundaries

| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Server/service compromised | Zero key material | None |
| User device compromised | Keychain + confirmation dialogs | Cannot defend fully compromised devices (same tier as hardware wallets) |
| Prompt injection | Platform endorsement + dialogs | User misclicks (re-passphrase mitigation) |
| LLM context leaks passphrase/recovery codes | **Token sessions** (passphrase entered locally in CLI; MCP receives 5-min single-use tokens) | Token window = 5 min + single-use |
| Share leaked (single point) | 2-of-3 threshold | Needs 2 shares leaked together |
| Passphrase + device both lost | — | **Unrecoverable (disclosed at registration, reasonable boundary)** |

## 9. Roadmap

| Stage | Content |
|-------|---------|
| M1 Core | core (generation/split/recover/reshare) + vector tests |
| M2 Forms | signer daemon + CLI + verify-sdk |
| M3 Protocol | signed_request v1 + MCP thin shell + double gate |
| M4 Open source | public release of independent repo + docs + audit (limited first, then fully open) |
| M5 Ecosystem | onboard the first business platform + publish integration guide |

## 10. Integration Relationship with Business Platforms (protocol-only coupling)

```
User Agent environment:
├── MCP server ① business platform  (business + binding + signed_request issuance)
├── MCP server ② wallet-service     (independent open source; signing/sharding/recovery)
└── no direct call: platform signs → Agent forwards to wallet service → signature returns
```

- Business platform side: retire legacy derived/proxy-wallet logic, add wallet-binding (bind/unbind/verify), withdrawals become signature-confirmed.
- `agents` table stores `wallet_address` + public key.
- The two MCP servers never interfere; they interact only via `signed_request`.

## Appendix: Related Docs in This Repository

- [SECURITY.md](SECURITY.md) / [SECURITY.en.md](SECURITY.en.md): security model (threat matrix, key lifecycle, fix records)
- [protocol/README.md](../protocol/README.md): signed_request v1 spec
