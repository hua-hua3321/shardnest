# shardnest

**Self-custodial, non-custodial wallet infrastructure** — key generation, Shamir secret sharing (2-of-3), signing, and recovery all happen on the user's own machine. The platform never touches key material. Any platform that speaks the `signed_request` v1 protocol can integrate.

> 中文版：[README.zh-CN.md](README.zh-CN.md)

## Why shardnest

- **Platform keeps zero key material** — private keys are generated, split, and signed 100% in the user's local environment. The platform only stores the public address.
- **Recoverable** — a 2-of-3 SSS split means losing your device, forgetting your passphrase, or losing one recovery code never means losing your wallet.
- **LLM-safe credential isolation** — passphrases and recovery codes never enter an LLM context. CLI generates single-use tokens (5 min TTL, 0600, atomic consume); MCP tools only receive token / local-file-path references.
- **Open protocol** — any platform can integrate via `signed_request` v1 (platform-endorsed signature requests), no lock-in.

## Quick start

Requirements: [Bun](https://bun.sh) ≥ 1.3.

```bash
bun install

# Create a wallet (interactive; passphrase is masked)
SHARDNEST_HOME=$(mktemp -d) bun packages/cli/src/index.ts init

# Commands
bun packages/cli/src/index.ts address                      # show address (no secret)
bun packages/cli/src/index.ts passphrase-token             # local passphrase → single-use token
bun packages/cli/src/index.ts unlock                       # local unlock → signing token
bun packages/cli/src/index.ts sign "<message>"             # EIP-191 personal sign
bun packages/cli/src/index.ts restore                      # recover from 2 recovery codes
```

Files under `~/.shardnest/` (override with `SHARDNEST_HOME`):

```
metadata.json        plaintext { address } — address is not secret
device-share.json    share ①, encrypted with passphrase (scrypt KEK + AES-GCM, 0600)
recovery-codes.txt   share ② (+③ only when email not sent) plaintext recovery codes (0600)
unlock/              token sessions: unlock-*.bin / passphrase-*.bin / consuming-*.bin
mnemonic.txt          (optional) 24-word mnemonic = full private key backup (single point, 0600)
```

## Key management model

- **Creation**: CSPRNG private key → SSS 2-of-3 split → share ① encrypted on device (passphrase), recovery codes ②+③ written to local file; optionally share ③ also emailed via SMTP (single share = zero information).
- **Signing**: platform issues a `signed_request` (endorsed with its private key) → MCP verifies endorsement, checks `wallet_address`, asks the user (approval gate) → consumes a local unlock token → signs in memory → wipes.
- **Recovery**: any 2 shares rebuild the same private key. `restore` cross-checks the derived address against the expected address / previous metadata to reject typo'd recovery codes.

## MCP server

```bash
SHARDNEST_PLATFORM_ADDRESS=<platform endorsement address> \
SHARDNEST_HOME=~/.shardnest \
bun packages/mcp-server/src/index.ts
```

Tools: `wallet_create` · `wallet_address` · `signed_request_sign` · `wallet_restore` · `wallet_mnemonic_export` · `wallet_wipe`.
Sensitive credentials are never tool arguments — use `passphrase_token` / `recovery_file_path` / `recovery_codes_file` instead.

Email backup (optional): `SHARDNEST_SMTP_HOST / PORT / USER / PASS / FROM / TLS`.

## CLI reference

All commands are interactive (passphrases & recovery codes are masked input).

| Command | Purpose | Key prompts / output |
|---------|---------|----------------------|
| `init` | Create wallet | masked passphrase → email (optional, sends share ③) → generate 24-word mnemonic? (default No) → prints recovery codes, saves files under `~/.shardnest/` |
| `address` | Show address | none (no secret needed) |
| `passphrase-token` | Generate passphrase token for MCP create/restore | masked passphrase → prints token (5 min, single-use, keep out of chats) |
| `unlock` | Generate unlock token for MCP signing | masked passphrase + recovery code → prints token |
| `sign <message>` | EIP-191 personal sign | masked passphrase + recovery code → `{address, signature}` |
| `restore` | Recover from 2 recovery codes | new masked passphrase → 2 masked recovery codes → expected address (optional, strongly recommended) → email (optional) |
| `restore-mnemonic` | Recover from 24-word mnemonic alone | new masked passphrase → 24 words → expected address (optional) → email (optional) |
| `mnemonic-export` | Export 24-word mnemonic from any 2 shares | mode a) device share + recovery code, or b) two recovery codes → writes `mnemonic.txt` |
| `wipe` | Permanently delete (irreversible) | choose scope: 1) saved files only, 2) everything → file list → confirm phrase `PERMANENT DELETE` |

### Mnemonic (optional, default off)

- Only **24 words** are supported: 12 words carry 128 bits < 256-bit private key (capacity constraint).
- **Standard BIP-39/44 semantics**: wallet root = 32-byte entropy (protected by 2-of-3 shares); the 24 words are the entropy's standard BIP-39 encoding and derive the account key via `m/44'/60'/0'/0/0` — **importable into MetaMask / Ledger / Trust Wallet for the same address**. Exportable anytime from any 2 shares.
- A mnemonic **equals the full private key (single point)** — leak = funds lost, no threshold protection. Store offline (paper/password manager), then run `wipe` (scope 1) to remove the local plaintext copy.
- Generated on `init` (opt-in) or exported anytime via `mnemonic-export` (any 2 of 3 shares); recovered via `restore-mnemonic`.

### Email backup (optional)

| Env var | Meaning |
|---------|---------|
| `SHARDNEST_SMTP_HOST` | SMTP server (required to enable) |
| `SHARDNEST_SMTP_PORT` / `TLS` | default 465 / true |
| `SHARDNEST_SMTP_USER` / `PASS` / `FROM` | credentials / sender (default USER) |

Recovery code integrity: CRC-256 (keccak256 first 4 bytes, 32-bit) — error-detection miss rate 1/2^32.

Backup distribution after init:
- **Email delivered** → local `recovery-codes.txt` holds only share ② (share ③ lives in the mailbox) — a full local compromise cannot move funds.
- **No email** → both shares ②③ stay local with a prominent warning; move one share offline or configure email.

### wipe — two scopes

| Scope | Deletes | Wallet after |
|-------|---------|-------------|
| 1) saved (default/recommended) | recovery codes + mnemonic (plaintext backups) | still usable (passphrase unlock) |
| 2) all | device share + backups + metadata + token sessions | must rebuild from saved codes/mnemonic |

Both scopes overwrite files 3× with random data before unlink (irreversible) and require the confirm phrase `PERMANENT DELETE`.

## MCP tools

Start the server:

```bash
SHARDNEST_PLATFORM_ADDRESS=<platform endorsement address> SHARDNEST_HOME=~/.shardnest \
bun packages/mcp-server/src/index.ts
```

Sensitive credentials never appear in tool arguments — they travel via local token files / file paths (LLM-isolated).

| Tool | Arguments | Notes |
|------|-----------|-------|
| `wallet_create` | `passphrase_token`, `email?`, `generate_mnemonic?` | returns `recovery_codes_file` / `mnemonic_file` paths (no plaintext to LLM); **rejects when a wallet already exists** (`WALLET_EXISTS`, no token consumed) — rebuild requires `wallet_wipe` (host approval) or CLI `init` interactive confirm |
| `wallet_address` | — | current address |
| `wallet_mnemonic_export` | — | approval-gated; writes 24-word mnemonic to local file, returns path only |
| `signed_request_sign` | `signed_request`, `unlock_token` | double-gated (platform endorsement + user approval); signs domain-separated request context (`wallet_address` / `platform_address` / `action` / `intent_hash` / `nonce` / `expires_at` / `user_id`) |
| `wallet_restore` | `recovery_file_path?` / `mnemonic_file_path?`, `passphrase_token`, `expected_address?`, `email?` | file paths must be inside the wallet dir |
| `wallet_wipe` | `scope?` (`saved` default / `all`) | approval-gated; returns removed file list |

## Platform integration (any business platform)

1. **Issue**: platform signs a `signed_request` with its own private key (`@wallet-service/protocol` `issueSignedRequest`).
2. **Sign**: user's Agent calls MCP `signed_request_sign` — endorsement verified, `wallet_address` checked, user confirms, local token consumed, EIP-191 signature returned.
3. **Verify**: platform runs `@wallet-service/verify-sdk` `recoverSigner(message, sig)` → recovered address must match the bound `wallet_address`.

See [protocol/README.md](protocol/README.md) for the `signed_request` v1 spec & JSON Schema.

## Architecture

```
core (pure crypto, no IO)          GF(2^8) SSS · keccak address · EIP-55 · scrypt KEK
signer                              WalletVault (sole key holder) · approval gate · token sessions
cli                                 commands · recovery-code CRC · SMTP backup
verify-sdk                          platform-side EIP-191 verification (verify-only, zero keys)
protocol                            signed_request v1 — platform endorsement issue/verify
mcp-server                          stateless shell (no keys) wiring the double gates
```

Cryptographic invariants are documented in [AGENTS.md](AGENTS.md) — read it before touching crypto code (GF(2^8) generator must be 3, EIP-191 hashing must stay byte-identical in three places, recovery-code CRC covers `index:hex`, memory zeroing on all paths).

## Testing

```bash
cd packages/<pkg> && bun test          # per-package
for p in core signer cli verify-sdk protocol mcp-server; do (cd packages/$p && bun test); done
```

## Documentation

- [Tutorial](docs/TUTORIAL.en.md) — end-to-end usage tutorial (create/sign/recover/wipe)
- [Integration](docs/INTEGRATION.en.md) — third-party platform integration guide
- [Development](docs/DEVELOPMENT.en.md) — development & modification guide (invariants, scenarios)
- [Changelog](docs/CHANGELOG.en.md) — modification history
- [Security model](docs/SECURITY.en.md) — threat matrix, key lifecycle, fix records
- [Design (DES-016)](docs/DES-016-self-custodial-wallet-service.en.md) — full design, roadmap
- [Protocol](protocol/README.md) — `signed_request` v1 spec & JSON Schema

## License

MIT
