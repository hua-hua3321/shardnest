---
title: shardnest Third-Party Integration Guide
date: 2026-08-09
status: active
last_reviewed: 2026-08-09
tags: ['integration', 'third-party', 'signed-request', 'verify-sdk']
---

# Third-Party Integration Guide

> For **business platforms** that need user wallet signature confirmations.
> Core principle: the platform holds **zero key material** — wallets are fully self-custodied; the platform only verifies signatures.

---

## Architecture overview

```
User Agent environment:
├── MCP server ① business platform   (business + address binding + signed_request issuance)
├── MCP server ② shardnest           (independent open source; signing/sharding/recovery)
└── interaction: platform issues -> Agent forwards to the wallet service -> signature returns
```

- Platform holds: its own endorsement private key (for issuance), user `wallet_address` (public info)
- Platform never holds: user passphrase, recovery codes, private keys, mnemonics — **no key material**
- Address binding = signature proves ownership; withdrawals = signature confirmation

---

## Step 1: Install dependencies

```bash
# Platform side needs: protocol (issuance) + verify-sdk (verification)
bun add @wallet-service/protocol @wallet-service/verify-sdk
# or reference via source workspace
```

**Platform must configure**: `SHARDNEST_PLATFORM_ADDRESS` (wallet-service startup env var) = the platform endorsement address.

## Step 2: Issue a signed_request (platform side)

```ts
import { issueSignedRequest } from '@wallet-service/protocol'

const request = issueSignedRequest({
  action: 'withdraw_confirm',          // business action (sign_message/sign_tx/bind_wallet/withdraw_confirm)
  intentHash: '0x' + 'ab'.repeat(32),  // business intent hash (e.g. withdrawal order hash)
  display: 'Confirm withdrawal of 0.5 ETH to 0x...',  // user-visible description
  userId: 'user-42',
  walletAddress: '0x7E5F...',          // target wallet address (previously bound)
  nonce: crypto.randomUUID(),          // one-time, replay protection (atomically consumed by the platform)
  expiresAt: Math.floor(Date.now()/1000) + 300,  // valid for 5 minutes
}, platformPrivateKey)
```

**Serialization spec** (canonicalBytes, must be identical across languages):
`v(1B) | action(len4+utf8) | intent_hash(len4+32B) | display(len4+utf8) | user_id(len4+utf8) | wallet_address(len4+20B) | nonce(len4+utf8) | expires_at(8B BE)`
— UTF-8 bytes + 4-byte big-endian length prefixes; **do NOT use JSON strings** (Unicode/int ambiguity breaks verification).

## Step 3: Sign on the Agent side (wallet service)

The user's Agent calls MCP `signed_request_sign` (args `signed_request` + `unlock_token`):

1. Gate 1: the wallet service verifies the platform endorsement (`verifySignedRequest`) — rejects non-platform issuances
2. Gate 2: host approval (default allows only `sign_message`; other actions require host config)
3. `wallet_address` must match the local wallet
4. Consume the unlock token (single-use) -> sign the domain-separated request context locally -> return `{ address, signature }`

## Step 4: Verify on the platform (verify-sdk)

```ts
import { recoverSigner } from '@wallet-service/verify-sdk'

const { message, signature } = signedResponse   // signature: 65 bytes r||s||v (hex)
const recovered = recoverSigner(message, hexToBytes(signature))
if (recovered.toLowerCase() !== boundWalletAddress.toLowerCase()) {
  throw new Error('Signature address does not match the bound address — rejected')
}
```

**The platform MUST perform the address-binding check** (signature validity alone is insufficient against cross-address replay).

## Address binding flow

1. The user creates a wallet (CLI `init` or MCP `wallet_create`) -> gets `wallet_address`
2. The platform initiates binding: issues a signed_request with `action: 'bind_wallet'`
3. The user signs (`signed_request_sign`) -> the platform recovers the address -> matches the user-declared address -> bound
4. After binding, the `agents` table stores `wallet_address` (public info, not a key)

**Rebinding**: withdraw the balance first -> unbind -> rebind with the new wallet.

## Withdrawal flow (signature confirmation)

```
User requests withdrawal -> platform creates an order -> issues withdraw_confirm signed_request
-> Agent calls signed_request_sign -> platform verifies + address-binding check -> transfers on success
```

## Error codes (returned by MCP tools)

| error | meaning | handling |
|-------|---------|----------|
| `BAD_SIGNATURE` | platform endorsement verification failed | check platform address/issuance (canonicalBytes consistency) |
| `EXPIRED` / `INVALID_FORMAT` | request expired / malformed | re-issue |
| `ACTION_NOT_ALLOWED` | action not in the whitelist | check the action enum |
| `WALLET_ADDRESS_MISMATCH` | target address != local wallet | check the wallet_address arg |
| `USER_REJECTED` | user/host denied approval | ask the user to confirm |
| `NO_WALLET` | no local wallet | wallet_create / CLI init first |
| `WALLET_EXISTS` | wallet already exists (create rejected) | wipe (host approval) or CLI confirm |
| `TOKEN_EXPIRED` / `TOKEN_CONSUMED` | token expired / already used | generate a new token |
| `NEED_SECOND_RECOVERY_CODE` | recovery needs 2 codes | provide the second one |

## Security requirements (platform side, must-read)

1. **Zero key material** — never collect/store user passphrases, recovery codes, private keys, or mnemonics
2. **Atomic nonce consumption** — replay protection
3. **Address-binding check** — verify the signature and compare against the bound address before withdrawals/sensitive ops
4. **Endorsement key security** — store the platform key in secure storage (KMS/HSM); sign only, never export
5. **Informed user** — `display` text must clearly describe what the user is about to confirm

## References

- Protocol details: [protocol/README.md](../protocol/README.md) + [signed-request-v1.schema.json](../protocol/signed-request-v1.schema.json)
- Verify SDK usage: [packages/verify-sdk/src/index.ts](../packages/verify-sdk/src/index.ts)
- End-to-end walkthrough: [TUTORIAL.en.md](TUTORIAL.en.md)
