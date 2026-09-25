# MonadGuard Registry

On-chain trust registry for agentic tools (MCP servers / skills) on Monad.
Scan a tool **before** an agent connects to it → signed receipt → anchored on-chain →
queryable trust history.

Hackathon: Monad **Metropolis**, 1 Sep – 13 Oct. Track 04 (Trust, Identity & AI Infrastructure)

[![test](https://github.com/poteshniy/monadguard/actions/workflows/test.yml/badge.svg)](https://github.com/poteshniy/monadguard/actions/workflows/test.yml)

## Live on Monad testnet (chain 10143)

| | |
|---|---|
| `ScanRegistry` | [`0xd0f6edd9be9cde91f671f4c2e129ee6105358436`](https://testnet.monadvision.com/address/0xd0f6edd9be9cde91f671f4c2e129ee6105358436) — deployed at block 61019528 |
| First anchor | [block 61019661](https://testnet.monadvision.com/tx/0xa4fd862f04f98843dd57d921ff3a2b644101474b43bd85bce7637f64e0d35612) — P-256 signature verified on-chain by the `P256VERIFY` precompile |
| Attestor | `0x79732eE50342D093402F7D5731d689D11E61c423` |
| **Registry site** | **https://monadguard.com** — browse trust history, check a manifest |
| API | https://api.monadguard.com/health |
| GraphQL — Envio Cloud | https://indexer.dev.hyperindex.xyz/4fe6364/v1/graphql (hosted by Envio, independent of our server) |
| GraphQL — self-hosted | https://graphql.monadguard.com/v1/graphql (read-only: `POST /v1/graphql` only) |

The two indexes are built independently from the same contract events and return identical data.

Check it yourself — no keys, no clone:

```bash
curl -s https://indexer.dev.hyperindex.xyz/4fe6364/v1/graphql -H 'content-type: application/json' \
  -d '{"query":"{ Scan { blockNumber verdict score txHash } Tool { id scanCount criticalCount } }"}'
```

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

## Passkey attestors — one passkey, many keys (mera)

Anyone can become an independent attestor at https://monadguard.com with nothing but a passkey.
One user-verified PRF evaluation through [`@category-labs/mera`](https://github.com/category-labs/mera)
yields 32 stable bytes; two keys are derived from them, domain-separated:

| key | curve | job |
|---|---|---|
| attestor key | P-256 | signs the receipt (JWS) and the anchor digest; `ScanRegistry` checks it on-chain with the **P256VERIFY** precompile |
| account key | secp256k1 (mera signing session → `toViemAccount`) | the `msg.sender` that registers the P-256 key and sends anchors |

The whole path runs in the browser: scan → sign receipt → publish it (content-addressed, the
server verifies the JWS against the key inside it) → anchor. No wallet, no seed phrase, no server
key. A synced passkey (Google Password Manager, iCloud Keychain) gives the **same** attestor on
every device; creating a second passkey gives a different one.

Server support: `POST /receipt` (publish a receipt signed by any attestor), `POST /rpc` (JSON-RPC
proxy, allow-listed methods, keeps the RPC key server-side), `POST /faucet` (one-time testnet gas
per new attestor address, daily caps). Source: `web/src/passkey.js`, bundle: `npm run build:web`.

## For integrators

**In an agent** — one call before connecting, fails closed:

```bash
npm i monadguard
```
```js
import { gate } from 'monadguard';
await gate({ kind: 'mcp', name: 'memory-server', origin: 'npm:@modelcontextprotocol/server-memory' });
// throws MonadGuardBlocked on CRITICAL, WARN, a stale verdict, or a tool nobody scanned
```

**In CI** — exit code 1 when a dependency is not cleared:

```bash
npx monadguard check npm:@acme/mcp-server
```

**As an MCP server** — the registry as a tool the agent calls itself:

```bash
claude mcp add monadguard -- npx -y monadguard-mcp
```

`check_tool` reads the chain before connecting; `scan_manifest` scans a `tools/list` payload you
already hold. Both read-only: anchoring needs an attestor key, which an agent running someone
else's prompt should not hold.

**In a contract** — this is why verdicts are anchored rather than kept in a database. Another
contract can check them itself, in the same transaction, without trusting an API to answer
honestly:

```solidity
if (!registry.isCleared(toolId, contentHash, attestor, 30 days)) revert ToolNotCleared();
```

`contentHash` pinning is the point: a tool that was clean last week can ship a poisoned manifest
today. Full example: [`contracts/examples/GatedRouter.sol`](contracts/examples/GatedRouter.sol).
Client source and options: [`client/`](client/).

**Who decides trust.** Anyone can register as an attestor and anchor verdicts; the registry
records who said what and does not gatekeep. Consumers pin the attestors they accept (`attestors:
[...]` in the client, the `attestor` argument on-chain). Reputation is a consumer-side policy,
not a privilege we grant.

## Relationship to ERC-8004

Complementary, not competing. ERC-8004 gives *agents* identity and reputation. MonadGuard
records attestations about the *tools those agents connect to* — the other half of the same
trust graph. An attestor in MonadGuard can itself be an ERC-8004 agent, which is the natural
composition: a registered agent whose job is scanning, whose findings are on the same chain
as its identity.

## Who adopts this, and why not roll their own

- **Agent runtimes and MCP clients** — a pre-connect gate. One RPC read (`isCleared`) or one
  GraphQL query before a tool is added to the context. They will not build this themselves
  because a scanner is not their product and a private registry has no network effect.
- **MCP registries and marketplaces** — a trust badge with provenance a user can verify
  independently, rather than a self-issued claim from the marketplace itself.
- **Enterprise agent platforms** — an audit trail with third-party attestation, which is
  exactly what an internal scan cannot provide.
- **On-chain agents on Monad** — the only way to gate tool use from inside a contract.

The reason not to roll your own is the same reason nobody runs a private CVE database: a
scan you keep to yourself is a private opinion. The registry's value is that it is shared,
signed, and cross-organisational, and it compounds with every attestor added. Rolling your
own gets you the 20% that is easy and none of the 80% that matters.

## Contract design decisions

- **Permissionless anchoring.** Anyone can attest; `msg.sender` is recorded as the attestor.
  Trust filtering happens at query time (filter by attestor), not via an owner allowlist.
  An owner-gated registry would make the "publicly verifiable" claim hollow, and judges on a
  trust/identity track will poke exactly there.
- **`toolId` ≠ `contentHash`.** `toolId` is the tool's stable identity; `contentHash` is the
  specific manifest version scanned. A tool accumulating versions over time *is* the trust
  history.
 
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
| `ADMIN_TOKEN` | required (`x-admin-token`) for `POST /anchor` without a signature, i.e. anchoring with the server key |
| `RATE_PER_MIN` | per-IP limit for `/scan*` and `/anchor*` (default 30) |
| `HOST` | bind address, default `127.0.0.1` — the reverse proxy is the only way in |
| `ENVIO_GRAPHQL_URL` | indexer the API reads trust history from (default the local Hasura) |
| `ENVIO_CLOUD_GRAPHQL_URL` | public Envio Cloud endpoint shown on the site |

### API

| route | does |
|---|---|
| `POST /scan` | `{kind,name,origin,content\|manifest}` → verdict, findings with fixes, signed receipt |
| `POST /scan/free` | 5-rule preview, no receipt — the free entry point |
| `POST /anchor/digest` | the exact digest a browser must sign, so the client never re-implements packing |
| `POST /anchor` | `{receiptHash, signature?}` → anchor tx now. Omit `signature` only on a node holding a key |
| `POST /anchor/queue` | `{receiptHash, signature}` → hand it to the batch worker instead of paying for a tx per scan |
| `GET /receipt/:hash` | the JWS (`application/jose`) — what `receiptURI` points at |
| `GET /` | the registry site (`web/index.html`), same origin as the API — no CORS, and the passkey `rpId` is the page's own host |
| `GET /registry` | all tools with their latest verdict, from Envio |
| `GET /registry/:toolId` | full trust history from Envio, plus findings and names from the attestor's cache |
| `GET /health` | chain, attestor, and a live P256VERIFY preflight |
| `GET /.well-known/jwks.json` | P-256 public key, so receipts verify without trusting this API |

### Public API rules

- A public `POST /scan` returns a signed receipt but is **never anchored** by this node. Otherwise
  anyone could spend our gas and write under our attestor identity.
- Anchoring happens only with an attestor signature: your own `{r,s}` via `/anchor` or `/anchor/queue`
  (the passkey path), or the server key behind `ADMIN_TOKEN`.
- Rate limited per IP. The API listens on loopback only; nginx is the single entry point.

### Surveying real MCP servers

`npm run capture -- --file scripts/capture/targets.json` installs each package **with
`--ignore-scripts`** in a throwaway container, then probes it for its real `tools/list` in a
second container with `--network none`, non-root, with memory and pid caps. `npm run survey`
scans what came back and writes `capture/REPORT.md`.

This executes third-party code, so it runs by hand, in Docker, never as a service and never on
request from the internet: an endpoint that did this would be a remote code execution hole next
to `PRIVATE_KEY`. `npm run survey -- --anchor` refuses to anchor a CRITICAL verdict on a real
published package unless it is listed in `capture/reviewed.json` — an on-chain CRITICAL is a
public accusation that cannot be edited later, so a human reads the findings first.

### Backups

Everything that is not on-chain — signed receipts and findings (`data/monadguard.db`), the attestor
identity and keys (`.env`) — is backed up nightly by `scripts/backup.sh`: consistent SQLite snapshot
via the online backup API, AES-256 (PBKDF2, 600k iterations) before it leaves the server, verified
to decrypt, pushed to a private repo with a deploy key scoped to that repo only, last 14 kept.

The passphrase lives in `/root/.monadguard-backup.pass` **and** in the operator's password manager.
Without the second copy a lost server means unreadable backups.

### Known limitations

- **The contract does not deduplicate `receiptHash`.** Only a registered attestor can anchor, and
  only under its own key, so nobody can inflate another attestor's record. An attestor could
  re-anchor its own receipts — but it could equally issue fresh ones, so dedup would not add
  protection. Consumers should weigh attestors, not raw scan counts.
- **Findings live off-chain.** The chain holds verdict, score and the receipt hash; the full
  findings are in the signed receipt at `receiptURI`, served by the attestor.
- **The first anchors carry a development `receiptURI`** (`http://localhost:8787/receipt/…`).
  On-chain data is immutable, so they stay that way. Receipts are content-addressed: every one is
  served at `https://api.monadguard.com/receipt/<receiptHash>`, and the API returns that as
  `receiptURL` next to the on-chain `receiptURI`. Anchors made after the fix carry the public URI,
  and `npm run doctor` fails in production if `BASE_URL` points at localhost.
- **Static analysis.** Rules catch known patterns in manifests and skill text. They do not execute
  the tool, and a clean verdict is not a guarantee.

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

`anchorScan` takes `(bytes32 r, bytes32 s)`, `attestorKey` is two bytes32, and
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

---

Built by [poteshniy](https://github.com/poteshniy). Parts of the implementation were written with AI assistance; every design decision, review and on-chain action is the author's.
