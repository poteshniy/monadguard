# monadguard

Check an MCP server or agent skill against the [MonadGuard](https://monadguard.com) on-chain
trust registry **before** your agent connects to it.

Every verdict was signed by an attestor with a P-256 key and verified on Monad by the
`P256VERIFY` precompile. This client only reads; there is no account, no key, nothing of ours
to trust.

```bash
npx monadguard check npm:@modelcontextprotocol/server-memory --name memory-server
```

Exit code 0 means a fresh CLEAN verdict exists; 1 means it does not — drop it into CI.

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
| `graphql` / `api` | public | point at your own indexer or mirror |

`check()` returns the full picture — every attestor's own latest verdict, scores, tx hashes —
so you can apply your own policy instead of ours.

### In a contract

Agents that act on-chain can check in the same transaction; see
[`contracts/examples/GatedRouter.sol`](https://github.com/poteshniy/monadguard/blob/main/contracts/examples/GatedRouter.sol).

MIT
