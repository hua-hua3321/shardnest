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
recovery-codes.txt   shares ②+③ plaintext recovery codes (0600, user responsibility)
unlock/              token sessions: unlock-*.bin / passphrase-*.bin / consuming-*.bin
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

Tools: `wallet_create` · `wallet_address` · `signed_request_sign` · `wallet_restore`.
Sensitive credentials are never tool arguments — use `passphrase_token` / `recovery_file_path` / `recovery_codes_file` instead.

Email backup (optional): `SHARDNEST_SMTP_HOST / PORT / USER / PASS / FROM / TLS`.

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

- [Security model](docs/SECURITY.md) — threat matrix, key lifecycle, fix records
- [Design (DES-016)](docs/DES-016-self-custodial-wallet-service.md) — full design, roadmap
- [Protocol](protocol/README.md) — `signed_request` v1 spec & JSON Schema

## License

MIT
