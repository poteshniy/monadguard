# monadguard

Check an MCP server or agent skill against the [MonadGuard](https://monadguard.com) on-chain
trust registry **before** your agent connects to it.

Every verdict was signed by an attestor with a P-256 key and verified on Monad by the
`P256VERIFY` precompile. This client only reads; there is no account, no key, nothing of ours
to trust.

```bash
npx monadguard check npm:@modelcontextprotocol/server-memory
```

Exit code 0 means a fresh CLEAN verdict exists; 1 means it does not — drop it into CI.

A tool's identity is `kind:origin#name`, where the name is the one the **server declares** —
npm's `server-memory` calls itself `memory-server`. That is deliberate: a server that renames
itself gets a new identity instead of inheriting an old clearance. Since you rarely know the
declared name up front, the origin alone is enough — the registry reports which identities it
has seen there, and the answer says which one it is about.

A name you *do* pass is a pin: `gate()` will not quietly answer about a different identity. If
it misses, the error names the one that would have matched.

```js
import { gate, check, MonadGuardBlocked } from 'monadguard';

// Fails closed: throws on CRITICAL, on WARN, on a stale verdict, and on a tool
// nobody has scanned. An unknown tool is not a safe tool.
try {
  await gate({ kind: 'mcp', name: 'memory-server', origin: 'npm:@modelcontextprotocol/server-memory' });
  await client.connect(transport);
} catch (e) {
  if (e instanceof MonadGuardBlocked) console.error('not connecting:', e.reason);
  else throw e;
}
```

### Options

| option | default | meaning |
|---|---|---|
| `attestors` | any | trust only these addresses; everyone else's verdict is ignored |
| `maxAgeDays` | 90 | a verdict older than this does not count |
| `allowWarn` | false | accept WARN |
| `allowUnknown` | false | accept a tool nobody has scanned |
| `contentHash` | — | require the clearance to cover *this exact* manifest (rug-pull protection) |
| `resolve` | `'auto'` | resolve the origin to a declared name when you gave none. `true`: also when the name you gave missed. `false`: never |
| `graphql` / `api` | public | point at your own indexer or mirror (also `MONADGUARD_GRAPHQL` / `MONADGUARD_API`) |

`check()` returns the full picture — every attestor's own latest verdict, scores, tx hashes —
so you can apply your own policy instead of ours.

### As an MCP server

Give the agent the registry as a tool it can call itself:

```bash
claude mcp add monadguard -- npx -y monadguard-mcp
```
```json
{ "mcpServers": { "monadguard": { "command": "npx", "args": ["-y", "monadguard-mcp"] } } }
```

| tool | does |
|---|---|
| `check_tool` | what the chain says about a tool, before connecting to it — every attestor's own verdict, the score, the tx |
| `scan_manifest` | scan a `tools/list` payload you already hold; returns findings with fixes, writes nothing |

Both are read-only. Anchoring needs an attestor key, which an agent running
someone else's prompt has no business holding. An unreachable registry comes
back as `UNKNOWN` with the reason, never as a pass.

### In a contract

Agents that act on-chain can check in the same transaction; see
[`contracts/examples/GatedRouter.sol`](https://github.com/poteshniy/monadguard/blob/main/contracts/examples/GatedRouter.sol).

MIT
