# MonadGuard Registry

On-chain trust registry for agentic tools (MCP servers / skills) on Monad.
Scan a tool **before** an agent connects to it → signed receipt → anchored on-chain →
queryable trust history.

Hackathon: Monad **Metropolis**, 1 Sep – 13 Oct. Track 04 (Trust, Identity & AI Infrastructure)

---

## Architecture

```
manifest text
    │
    ├─► scanner/  (40 SKILL rules + 10 MCP rules)   
    │        └─► verdict + score + findings
    │
    ├─► receipt.js  ES256 sign over JCS             
    │        ├─► receipt JWS  ──► receipt_uri (served by /receipt/:hash)
    │        └─► anchor sig (r,s) over anchorDigest(...)
    │
    ├─► viem  anchorScan(toolId, contentHash, verdict, score, receiptHash, uri, r, s)
    │        └─► Monad  ──► P256VERIFY(0x100) ──► event ScanAnchored
    │
    └─► Envio HyperIndex  ──► GraphQL: Tool / ToolVersion / Scan / Attestor
                                  └─► GET /registry/:toolId  (trust history)
```

Chain holds the tamper-evident index. Receipts live off-chain. Aggregation lives in Envio.
Nothing is duplicated for the sake of looking busy.

## Contract design decisions

- **Permissionless anchoring.** Anyone can attest; `msg.sender` is recorded as the attestor.
  Trust filtering happens at query time (filter by attestor), not via an owner allowlist.
  An owner-gated registry would make the "publicly verifiable" claim hollow, and judges on a
  trust/identity track will poke exactly there.
- **`toolId` ≠ `contentHash`.** `toolId` is the tool's stable identity; `contentHash` is the
  specific manifest version scanned. A tool accumulating versions over time *is* the trust
  history.
  manifest revision.
- **Timestamps from `block.timestamp`,** never calldata. A caller-supplied `ts` proves nothing.
- **History in events, not storage.** Storage holds only the O(1) "latest" pointer for on-chain
  reads (`isCleared` lets another contract gate on a fresh CLEAN verdict).
- **`anchorScanBatch`** exists so the demo can push volume — the only way "Monad is fast"
  means anything in a submission.

## Build

```bash
npm i
npm run compile                       # → build/ScanRegistry.json
npm run doctor                        # preflight: run this before and after every step
npm test                              # parity + receipts + attestor, all offline

# deploy (Alchemy RPC; falls back to the public endpoint if ALCHEMY_KEY is unset)
PRIVATE_KEY=0x… ALCHEMY_KEY=… CHAIN_ID=10143 npm run deploy    # → deployment.json

# prove the whole path on-chain, including a negative control
PRIVATE_KEY=0x… ALCHEMY_KEY=… MONADGUARD_PRF_HEX=$(openssl rand -hex 32) npm run e2e

npm run dev                           # API on :8787
```

Then wire `deployment.json` (`address`, `deployBlock`) into `indexer/config.yaml`.

### Doctor

`npm run doctor` checks, in dependency order: Node version, the native sqlite build, whether
the compiled artifact predates the P256VERIFY rewrite, `.env` contents, RPC reachability and
chain ID agreement, **P256VERIFY at 0x100**, wallet balance, deployed code + attestor
registration + anchor count, sqlite writability and queue depth, and whether
`indexer/config.yaml` still holds the placeholder address. `WARN` never fails the run; `FAIL`
exits 1.

The precompile check signs a fresh vector at runtime rather than using a canned one, and that
detail is the whole check: an `eth_call` to an address with no code **succeeds and returns
empty**, which is also RIP-7212's failure encoding. A hardcoded vector cannot distinguish
"precompile missing" from "bad input". A signature generated seconds earlier is known-good, so
anything but `1` means the precompile is absent or broken — and there is no project without it.

### Anchoring: one at a time vs batched

`POST /anchor` sends a transaction immediately. `POST /anchor/queue` stores the browser's
`(r, s)` and lets `npm run worker` sweep them into one `anchorScanBatch`.

The batch path is not an optimisation, it is the passkey path. A PRF ceremony requires user
verification and that is not configurable, so the browser derives once, signs N receipts from
the key held in memory, and hands them over — anchoring those one transaction at a time would
mean N wallet prompts for one biometric. It also means a failed anchor is a retry rather than
a lost scan, and it is the only way the demo pushes enough volume for "Monad is fast" to mean
anything.

One invalid signature reverts the whole batch, so after `WORKER_POISON_AFTER` consecutive
failures the worker drops to one-by-one, marks the offending row `poison`, and lets the rest
through.

| var | default | |
|---|---|---|
| `BATCH_MAX` | 25 | rows per `anchorScanBatch` |
| `WORKER_INTERVAL_MS` | 15000 | sweep interval |
| `WORKER_MAX_BACKOFF_MS` | 300000 | ceiling on failure backoff |
| `WORKER_POISON_AFTER` | 3 | whole-batch failures before isolating rows |

### Running on a server (PM2)

```bash
npm i --omit=dev && npm run compile
chmod 600 .env
pm2 start ecosystem.config.cjs
pm2 save
```

`NODE_ENV=production` is set in the PM2 env deliberately: it disables the
well-known dev attestor key, so a missing `MONADGUARD_PRF_HEX` fails loudly
instead of quietly anchoring with a key every reader of this repo has.

The worker runs as exactly one instance. Two of them sweep the same SQLite queue,
build overlapping batches from the same rows and burn gas anchoring duplicates —
`instances: 1` is load-bearing, not a default.

Bind the API behind nginx before pointing a domain at it. The domain is not a
deployment detail here: `rpId` is domain-bound, so whatever host serves the UI is
the host the demo passkey must be created on.

### Secrets

`npm run dev` and `npm run deploy` refuse to start if `.env` is tracked, `.gitignore` misses
it, or any tracked file contains something key-shaped. `npm run hooks` installs the same check
as a pre-commit hook. The repo is a public deliverable — this is the cheapest possible way to
not hand out an RPC key or the attestor's private key with it.

### Environment

| var | purpose |
|---|---|
| `PRIVATE_KEY` | funded testnet account; pays gas, and is the attestor address on-chain |
| `ALCHEMY_KEY` | Monad RPC transport (bounty). `RPC_URL` overrides it |
| `REGISTRY_ADDRESS` | overrides `deployment.json` |
| `MONADGUARD_PRF_HEX` | 32 bytes standing in for the passkey PRF output — **headless/CI only**; in production the browser holds this |
| `AUTO_ANCHOR=1` | `/scan` anchors immediately instead of returning a pending anchor |
| `BASE_URL` | public origin used to build `receiptURI` |

### API

| route | does |
|---|---|
| `POST /scan` | `{kind,name,origin,content\|manifest}` → verdict, findings with fixes, signed receipt |
| `POST /scan/free` | 5-rule preview, no receipt — the free entry point |
| `POST /anchor/digest` | the exact digest a browser must sign, so the client never re-implements packing |
| `POST /anchor` | `{receiptHash, signature?}` → anchor tx now. Omit `signature` only on a node holding a key |
| `POST /anchor/queue` | `{receiptHash, signature}` → hand it to the batch worker instead of paying for a tx per scan |
| `GET /receipt/:hash` | the JWS (`application/jose`) — what `receiptURI` points at |
| `GET /registry/:toolId` | trust history from the local cache + on-chain scan count |
| `GET /health` | chain, attestor, and a live P256VERIFY preflight |
| `GET /.well-known/jwks.json` | P-256 public key, so receipts verify without trusting this API |

## Networks

| | Chain ID | Envio |
|---|---|---|
| Monad mainnet | **143** | GOLD |
| Monad testnet | **10143** | GOLD |

**Locked to testnet 10143** — free gas, and batch
anchoring for the demo would otherwise cost real MON.

---

## PRF constraints — architectural, not details

- **PRF is browser-only.** WebAuthn is a browser API and a passkey is bound to an `rpId`
  (a domain). Node cannot run a ceremony. Receipt signing therefore happens client-side:
  server scans → returns the canonical payload → browser signs → anchor.
- **Every ceremony needs user verification** (biometric/PIN), and it is not configurable.
  No autonomous mass-signing. Derive once per session, hold in memory, sign N receipts,
  batch-anchor them. `anchorScanBatch` is now load-bearing, not decoration.
- **`rpId` is a domain.** A passkey created on `localhost` produces different PRF output
  than one created on the production domain. **Pick and deploy the final domain before
  creating the demo passkey**, or the cross-device demo breaks on judging day.
- **Cross-device only works with a synced platform authenticator** (iCloud Keychain,
  Google Password Manager, 1Password) — not a device-bound hardware key.
- **On the second device, SELECT the existing passkey, never create one.** Same rpId +
  same user handle overwrites the credential and the replacement gets a fresh PRF; Mera
  mints a random handle per creation, so a "create" on device two silently yields a
  different attestor identity. This is the single most likely way the live demo fails.

## P-256 receipts, verified on-chain

PRF returns exactly 32 bytes — a valid seed for either ed25519 or secp256r1. Monad exposes
the RIP-7212 / EIP-7951 `P256VERIFY` precompile at `0x0000...0100` (160-byte input:
hash ‖ r ‖ s ‖ x ‖ y; returns 1 on success). Signing receipts on P-256 lets `anchorScan`
**verify the attestor's signature on-chain** rather than record a hash of it: you cannot
anchor a verdict you did not sign. Ed25519 has no such precompile.

**DONE.** `anchorScan` takes `(bytes32 r, bytes32 s)`, `attestorKey` is two bytes32, and
`_verifyP256` staticcalls `0x100` with `hash‖r‖s‖x‖y`. Failure is surfaced as `BadSignature`
rather than a bubbled revert, and empty returndata (the RIP-7212 failure encoding) counts as
failure — verified in the local-EVM test, where no precompile exists at `0x100`.

### What the signature actually covers — and why it is not the receipt hash

Signing an opaque `receiptHash` would have proved only that the attestor signed *some*
receipt. Nothing would stop it anchoring `verdict = CLEAN` while holding a signature over a
receipt that said CRITICAL: the chain cannot re-derive `sha256(JCS(payload))` from calldata.

So the signed message is computed on-chain instead:

```
anchorDigest = sha256(
  "MonadGuard/anchor/v1" ‖ chainId ‖ registryAddress ‖ attestor ‖
  toolId ‖ contentHash ‖ verdict ‖ score ‖ receiptHash
)
```

Every anchored field is inside it, so a signature cannot be moved onto a different verdict.
`chainId ‖ registryAddress` stops replay onto another chain or another deployment, and
`attestor` stops one address anchoring another's signed receipt as its own. `receiptURI` is
deliberately excluded — it is a mutable pointer owned by the same attestor, so binding it
would only force a re-sign whenever the receipt is rehosted.

`registerAttestor` requires proof of possession over the same shape
(`"MonadGuard/register/v1" ‖ chainId ‖ registry ‖ attestor ‖ x ‖ y`). Without it, an address
could register someone else's public key and inflate its own attestor stats by re-broadcasting
their signed receipts.

Cost of the binding: two signatures per scan from one key (JWS + anchor), which is one PRF
ceremony either way, plus an on-chain `sha256` (~100 gas) per anchor.

**Solidity/JS digest parity is a test, not a hope:** `test/parity.test.mjs` executes the
compiled bytecode in a local EVM and compares `anchorDigest` and `registrationDigest` against
the JS implementation. A one-byte disagreement between `abi.encodePacked` and viem's
`encodePacked` would otherwise show up as every anchor reverting with `BadSignature`.
