# MonadGuard — submission copy

Everything the forms will ask for. Copy-paste, don't rewrite under deadline pressure.

Track: **Trust, Identity & AI Infrastructure** ($30,000 / 3 winners × $10,000)
Deadline: **Oct 14, 2026, 05:59 GMT+2**

---

## Name

`MonadGuard`

## One-line description (118 chars)

> On-chain trust registry for MCP servers and agent skills — scan before connect, every verdict signed and anchored on Monad.

---

## Short description (~100 chars)

> Scan an MCP server before your agent connects. Verdicts signed and anchored on Monad.

## Medium description (~300 chars)

> Agents connect to MCP servers and skills by name, with no way to check what they're loading. MonadGuard scans the manifest for prompt injection, credential exfiltration and backdoors, signs the verdict, and anchors it on Monad — so any agent or registry can query a tool's verifiable trust history first.

## Long description (~500 chars)

> An MCP server's manifest goes straight into an agent's context, where it acts as executable influence. Today agents connect blind. MonadGuard scans a tool's manifest against 50 threat rules, issues an ed25519-signed receipt, and anchors the verdict on Monad. Envio HyperIndex turns those anchors into a queryable trust history: every scan of a tool, by whom, when, with what result — public, immutable, and not owned by any single platform. Attestation is permissionless; trust is filtered by attestor, not gatekept.

---

## Full description

### The problem

When an agent connects to an MCP server or loads a skill, the tool's manifest — its
descriptions, parameter docs, and embedded prompts — is injected directly into the agent's
context window. That text is not data. It is executable influence over a system that holds
credentials and can act.

A hostile or compromised tool can exfiltrate secrets, override prior instructions, or install
a persistent backdoor in the agent's behaviour. And an agent has no way to check any of this
**before** it connects. It resolves a name, pulls a manifest, and trusts it.

The existing governance stack does not cover this. Agent-observability and policy platforms
inspect *traces* — they judge behaviour after it has already happened, inside one company's
deployment. Nobody inspects the artifact at connect time by its content, and nobody keeps a
public record of what was found. The result: every organisation that scans a tool throws the
finding away, and the next organisation starts from zero.

### What MonadGuard does

1. **Scan.** A tool's manifest is checked against 50 threat rules across seven categories —
   prompt injection, credential exfiltration, backdoors, privilege escalation, wallet access,
   data leakage, and unsafe execution. Output: a verdict (CLEAN / WARN / CRITICAL), a 0–100
   risk score, and specific findings with human-readable fixes.
2. **Sign.** The result is canonicalised (JCS) and signed with ed25519, producing a JWS
   receipt that anyone can verify offline against the attestor's published key.
3. **Anchor.** The receipt hash, verdict, score, and the tool's content hash go on-chain via
   `ScanRegistry.anchorScan()` on Monad. Timestamps come from the block, never the caller.
4. **Query.** Envio HyperIndex turns the event stream into a GraphQL trust history:
   every scan of a tool, by which attestor, on which manifest version, with what verdict.
   `GET /registry/:toolId` returns that history; `isCleared()` lets another *contract* gate
   on a fresh CLEAN verdict on-chain.

The scanner is the cheap part. **The registry is the product** — the accumulating, publicly
verifiable record that makes one scan useful to everyone who comes after it.

### Why this belongs on-chain, and why permissionless

A trust registry whose operator can silently rewrite history is not a trust registry; it is a
vendor's opinion with extra steps. Anchoring makes the record append-only and independently
auditable, and it removes the operator from the trust path entirely.

Anchoring is therefore **permissionless**: anyone can attest, and `msg.sender` is recorded as
the attestor. There is no owner allowlist, because an allowlist would simply move the
capture point rather than remove it. Sybil resistance lives in the query layer — consumers
filter by the attestors they trust, and attestors publish the ed25519 key their receipts are
signed with. The registry stays neutral; trust is a client-side policy.

`toolId` is a tool's stable identity; `contentHash` is the specific manifest version scanned.
A tool accumulates versions over time, and that accumulation is the trust history: you can
see that a package was clean for nine releases and turned CRITICAL on the tenth.

### Relationship to ERC-8004

Complementary, not competing. ERC-8004 gives *agents* identity and reputation. MonadGuard
records attestations about the *tools those agents connect to* — the other half of the same
trust graph. An attestor in MonadGuard can itself be an ERC-8004 agent, which is the natural
composition: a registered agent whose job is scanning, whose findings are on the same chain
as its identity.

### Who adopts this, and why not roll their own

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

---

## Envio bounty paragraph

> MonadGuard's registry is not readable without an indexer. The contract emits `ScanAnchored`
> per attestation; the product — a tool's trust history across versions and attestors — only
> exists as an aggregate over that event stream. Envio HyperIndex builds the `Tool`,
> `ToolVersion`, `Scan` and `Attestor` entities that back every read path in the app:
> `GET /registry/:toolId`, the public registry view, and the per-attestor filtering that makes
> permissionless attestation safe to consume. Remove HyperIndex and there is no registry left,
> only a write-only contract.

---

## Deliverables checklist

- [ ] Project logo/graphic — JPG/JPEG/PNG/WEBP, max 3MB
- [ ] Public GitHub repo, accessible by `metropolis@hackathon.monad.xyz`
- [ ] Technical demo video — max 3 min, **live working product** (not slides, not code walkthrough)
- [ ] Pitch video — max 2 min: who, what problem, why building it
- [ ] Live product link — Monad **Mainnet or Testnet**, with access instructions + any test creds
- [ ] Product advertisement — max 30s, optional, not judged

---

## Mera bounty paragraph

> An attestor's authority in MonadGuard is its ed25519 receipt-signing key — the key that makes a
> scan verdict verifiable offline, independent of our server. Storing that key anywhere is the
> whole problem: on a laptop it is exfiltratable, on our server it makes us the trust root we
> claim not to be. So we don't store it. The signing key is derived from a Mera PRF namespace
> (`monadguard/attestor/v1`) and exists only in memory for the length of a session. A second,
> isolated namespace (`monadguard/vault/v1`) encrypts draft findings before they are anchored.
> Neither is a wallet key and neither signs a transaction — the PRF output does identity and
> encryption work, not account work. The cross-device proof is the demo: open MonadGuard on a
> fresh browser profile, tap the same passkey, and the same attestor public key reappears and
> verifies receipts already anchored on Monad — with nothing having been persisted to disk or
> server anywhere in between.

## Alchemy bounty paragraph

> Every anchoring transaction and every on-chain read (`isCleared`, `latestVerdict`) routes
> through Alchemy's Monad RPC, including the batch anchoring path used to backfill the registry.
