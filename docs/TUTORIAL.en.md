---
title: shardnest End-to-End Tutorial
date: 2026-08-09
status: active
last_reviewed: 2026-08-09
tags: ['wallet', 'tutorial', 'CLI', 'MCP', 'recovery', 'mnemonic']
---

# shardnest Tutorial (End-to-End)

> Walk through the full wallet lifecycle: **create -> backup -> daily use -> recover -> wipe**.
> All commands are interactive (passphrases & recovery codes are masked input, never echoed to the terminal).

---

## Scenario A: Create a wallet (3 minutes)

### 1. Install

```bash
git clone https://github.com/hua-hua3321/shardnest.git
cd shardnest && bun install
```

### 2. Initialize

```bash
bun packages/cli/src/index.ts init
```

Interactive flow:

```
Set passphrase (>=12 chars, encrypts device share): ********   <- at least 12 chars, mix case/digits/symbols
Email (optional, auto-sends backup share...): user@example.com <- optional; share 3 is emailed (3-location distribution)
Generate a 24-word mnemonic backup? (default: No) [y/N]: n     <- default No; power users may choose y (see below)
✅ Wallet created
Address: 0xAFD0...
⚠️  Recovery codes (save now; if the device is lost they cannot be recovered):
  sn1-2-<64 hex>-<8 hex crc>
  sn1-3-<64 hex>-<8 hex crc>
```

**Do these 3 things right after creation**:
1. **Save the recovery codes** — `recovery-codes.txt` is written to `~/.shardnest/`; **do NOT hand-copy** (64-char hex), just move the file
2. **Check your mailbox** — if an email was provided, share 3 was sent (local keeps only 1 share = true 3-location distribution)
3. **Verify backup layout** — without email, 2 shares stay local with a prominent warning; move one share offline

> **Mnemonic (optional)**: the 24-word mnemonic follows standard BIP-39/44 (importable into MetaMask for the same address).
> But the mnemonic = full private key (single point): a leak means total loss. Regular users should skip it;
> power/high-value users should write it offline, then run `wipe` (scope 1) to remove the local plaintext copy.

### 3. Show address

```bash
bun packages/cli/src/index.ts address
```

---

## Scenario B: Daily signing (CLI and MCP paths)

### Path 1: CLI direct signing

```bash
bun packages/cli/src/index.ts sign "hello shardnest"
# passphrase + recovery code (masked) -> { address, signature }
```

### Path 2: MCP (Agent scenario, credential isolation)

1. **Generate a passphrase token** (plaintext passphrase never enters the LLM):

```bash
bun packages/cli/src/index.ts passphrase-token
# enter passphrase -> token (valid 5 min, single-use)
```

2. **Create the wallet** (MCP `wallet_create`, arg `passphrase_token`)
3. **Generate an unlock token** (before signing):

```bash
bun packages/cli/src/index.ts unlock
# passphrase + recovery code -> unlock token (valid 5 min, single-use)
```

4. **Sign** (MCP `signed_request_sign`, args `signed_request` + `unlock_token`):
   double gate = platform endorsement verification + host approval; signs `action:intent_hash`

> Recovery-source guidance: `unlock`/`sign` print where the second factor should come from
> (email share 3 / offline copy) based on local storage state — follow the hint.

---

## Scenario C: Recover the wallet

### Method 1: 2 recovery codes (new device / lost passphrase)

```bash
bun packages/cli/src/index.ts restore
# new passphrase -> recovery code 1 -> recovery code 2 -> expected address (optional, strongly recommended) -> email (optional)
# ✅ Wallet recovered (address cross-check passed)
```

### Method 2: 24-word mnemonic alone

```bash
bun packages/cli/src/index.ts restore-mnemonic
# new passphrase -> 24 words (space-separated, checksum-validated) -> expected address (optional) -> email (optional)
```

> Old recovery codes / old email shares can still recombine the same private key — **destroy old carriers** after recovery.

### Method 3: Export mnemonic from any 2 shares (backup)

```bash
bun packages/cli/src/index.ts mnemonic-export
# mode a) device share + recovery code (needs passphrase)  or b) two recovery codes
# -> writes mnemonic.txt (24 words = full private key; write it down and store securely)
```

---

## Scenario D: Permanent wipe (irreversible)

```bash
bun packages/cli/src/index.ts wipe
```

```
📌 Choose deletion scope:
  1) Delete only "must-save" plaintext backups (recovery codes/mnemonic) — wallet stays (recommended)
  2) Delete everything on this machine (wallet too)
Choose [1/2]: 1
📄 The following files will be deleted (3x overwrite, irreversible):
  - recovery-codes.txt
  - mnemonic.txt
📌 Before proceeding, confirm:
    1. Recovery codes/mnemonic saved somewhere safe — this is the only recovery path
    2. Business platform bindings etc. are finalized
Type the confirm phrase "PERMANENT DELETE": ********
✅ Permanently deleted 2 files
```

> Make sure recovery codes/mnemonic are safely saved before wiping — after deletion there is no local recovery path.

---

## Language switching

The CLI auto-switches between Chinese and English based on the system language (`zh*` -> Chinese, otherwise English).
Explicit override: `SHARDNEST_LANG=zh|en`.

```bash
SHARDNEST_LANG=en bun packages/cli/src/index.ts init   # force English
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Passphrase wrong, or device share corrupted" | Wrong passphrase, or corrupted device share | Re-check passphrase; if corrupted, `restore` from recovery codes |
| "Wallet already exists" | Duplicate init (anti-silent-overwrite, W9) | `wipe` or `restore` first, or confirm via CLI interactive recreate |
| "Recovery code verification failed" | Typo/corruption (caught by 32-bit CRC) | Re-check the recovery code |
| "Address mismatch with local wallet" | Wrong recovery code | Re-check codes, make sure they belong to the same wallet |
| "Invalid mnemonic" | Typo / wrong wordlist (checksum rejection) | Re-check the 24 words |
| Default approval rejects wipe | MCP path requires host-injected approval (OS dialog) | Host configures an approval handler; CLI path unaffected |

---

## References

- Full command reference: [README.md](../README.md)
- Security model: [SECURITY.en.md](SECURITY.en.md)
- Changelog: [CHANGELOG.en.md](CHANGELOG.en.md)
- Development guide: [DEVELOPMENT.en.md](DEVELOPMENT.en.md)
- Third-party integration: [INTEGRATION.en.md](INTEGRATION.en.md)
