---
title: shardnest Development & Modification Guide
date: 2026-08-09
status: active
last_reviewed: 2026-08-09
tags: ['development', 'contribution', 'guide']
---

# Development & Modification Guide

> How to modify this project: structure, invariants, workflow, common scenarios.

---

## Workspace layout

```
packages/
├── core/         # pure crypto: entropy, SSS (GF(2^8)), BIP-39/44 derivation, scrypt/AES-GCM
├── signer/       # signing daemon: WalletVault (derived-key injection -> EIP-191 sign -> wipe), token sessions
├── cli/          # CLI form (human scenarios; i18n zh/en)
├── mcp-server/   # MCP thin shell (no keys; 6 tools; approval gates)
├── verify-sdk/   # platform-side verify SDK (verify-only)
└── protocol/     # signed_request v1 spec (canonicalBytes + JSON Schema)
docs/             # security model / tutorial / changelog / development / integration (zh + en)
```

## Critical invariants (must understand before changing — violation breaks security)

1. **GF(256) generator must be 3** (0x03) — element 2 has order 51, not primitive
2. **EIP-191 hashing identical in 3 places**: `vault.ts` / `verify-sdk` / `protocol` `personalMessageHash` byte-identical
3. **Recovery-code CRC covers index:hex** (32-bit) — index in [1,255], hex format, CRC triple check
4. **Private-key range check**: 0 < priv < n (`assertValidPrivateKey`)
5. **Sensitive-material zeroing**: entropy, private key, BIP-39 seed, plaintext shares must `fill(0)` after use (including exception paths, via finally)
6. **Atomicity**: init/restore fail-able ops first; failure rolls back all three files (incl. recovery/mnemonic)
7. **reshare semantics**: old share sets still recombine the same key — warn about physical cleanup after reshare
8. **Credential isolation**: plaintext passphrase/recovery codes/mnemonic NEVER enter the LLM — MCP uses token/file-path channels only
9. **Secure by default**: irreversible/high-risk MCP ops (wipe/mnemonic export) are denied by default; host approval required

## Common modification scenarios

### Scenario 1: Change scrypt params

```ts
// packages/core/src/keys.ts
export const SCRYPT_OPTS = { N: 2 ** 17, r: 8, p: 1, dkLen: 32 } as const
```

- New wallets use the new params automatically; **old wallets decrypt with persisted kdf params (O1), unaffected**
- v1 wallets without a kdf field fall back to `LEGACY_SCRYPT_OPTS_V1` (2^16) — **do not change this constant**

### Scenario 2: Add an MCP tool

1. Add `server.tool(...)` in `packages/mcp-server/src/index.ts`
2. Sensitive inputs (passphrase/recovery codes) must use token or file-path channels — **no plaintext args**
3. High-risk ops (irreversible/private-key related) need an approval gate; extend the `ApprovalRequest.action` union
4. Outputs must not contain plaintext sensitive data (return file paths)
5. Add tests (mcp.test.ts)

### Scenario 3: Modify the derivation path (careful)

- `BIP44_PATH` lives in `packages/core/src/mnemonic.ts`
- **Changing the path changes every new wallet address = MetaMask incompatible** — the W15 pin test will fail
- Must update the W15 pinned address (verify via MetaMask/iancoleman first)

### Scenario 4: Change the recovery-code format

- `encodeRecoveryCode`/`decodeRecoveryCode` in `packages/cli/src/commands.ts`
- Keep dual-width compatibility (old format still decodes) or accept a breaking change and sync docs
- The 32-bit CRC covering index:hex must not be weakened

### Scenario 5: Change the protocol (signed_request)

- `canonicalBytes` in `packages/protocol/src/signed-request.ts` — a **cross-language contract**; any change is breaking
- Version negotiation: bump `v` and keep legacy compatibility, or accept a breaking change with a clear announcement
- Sync `protocol/README.md` + `signed-request-v1.schema.json`

## Testing

```bash
# full suite (6 packages)
for p in core signer cli verify-sdk protocol mcp-server; do (cd packages/$p && bun test); done

# single package
cd packages/cli && bun test ./test/commands.test.ts
```

- Type check must be 0 errors: `bunx tsc --noEmit`
- Crypto changes must add vector/fixture tests (see W15 address pin, C1 real v1 fixture)

## Commit conventions

- Atomic commits: one logical change per commit
- Message: `feat|fix|docs|test: summary` + details
- Run the full suite + tsc before committing
- Push to GitHub (hua-hua3321/shardnest); retry when the network is unstable

## Release process

See the release-process section of [CHANGELOG.en.md](CHANGELOG.en.md).
