/**
 * MonadGuard API.
 *
 *   POST /scan              full scan -> signed receipt (-> optional anchor)
 *   POST /scan/free         5-rule preview, no receipt
 *   POST /anchor            anchor a receipt already produced by /scan
 *   GET  /receipt/:hash     the JWS itself (this is what receiptURI points at)
 *   GET  /registry/:toolId  trust history for a tool
 *   GET  /registry          recently scanned tools
 *   GET  /health            chain + attestor + precompile status
 *   GET  /.well-known/jwks.json
 *
 * The browser (passkey) path posts its own (r, s) to /anchor. The server-side
 * key is only used when MONADGUARD_PRF_HEX is set, i.e. headless demo and CI.
 */
import './env.js';
import { readFileSync } from 'node:fs';
import { Hono } from 'hono';
import { compress } from 'hono/compress';
import { parseEther, isAddress, getAddress } from 'viem';
import { serve } from '@hono/node-server';
import { scan } from './scanner/engine.js';
import { scanMCP } from './scanner/mcp.js';
import { rulesVersion } from './scanner/version.js';
import { freeScan } from './free_scan.js';
import { recommend } from './recs.js';
import { buildReceipt, receiptHash as hashReceipt, signReceiptJws, verifyReceiptJws, decodeReceipt, jwks, anchorDigest, signDigest, toVerdict } from './receipt.js';
import { toolId as deriveToolId, contentHash as deriveContentHash } from '../scripts/toolid.mjs';
import { loadAttestor, publicAttestor } from './keys.js';
import * as db from './db.js';
import * as chain from './chain.js';
import * as envio from './envio.js';

const PORT = Number(process.env.PORT ?? 8787);
const BASE_URL = process.env.BASE_URL ?? `http://localhost:${PORT}`;
const AUTO_ANCHOR = process.env.AUTO_ANCHOR === '1';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || null;

// Per-IP fixed window. Scanning is CPU-only but public; a hackathon Discord
// will poke it. nginx must pass X-Real-IP, otherwise everyone shares one bucket.
const RATE = Number(process.env.RATE_PER_MIN ?? 30);
const hits = new Map();
const limited = (ip) => {
  const w = Math.floor(Date.now() / 60000), k = `${ip}:${w}`;
  const n = (hits.get(k) ?? 0) + 1; hits.set(k, n);
  if (hits.size > 5000) for (const key of hits.keys()) if (!key.endsWith(`:${w}`)) hits.delete(key);
  return n > RATE;
};

const key = loadAttestor({ allowDevKey: process.env.NODE_ENV !== 'production' });
const app = new Hono();

const severity = (sev) => (sev >= 90 ? 'CRITICAL' : sev >= 70 ? 'HIGH' : sev >= 40 ? 'MEDIUM' : 'LOW');
const withFixes = (findings) => findings.map((f) => ({ ...f, severity: severity(f.sev), recommendation: recommend(f.cat) }));

// ─── Health ───────────────────────────────────────────────────────────────
app.get('/health', async (c) => {
  const out = {
    ok: true,
    chainId: chain.CHAIN_ID,
    registry: chain.REGISTRY,
    rpc: chain.RPC_URL.replace(/\/v2\/.*$/, '/v2/***'),
    // Which ruleset this process is signing with. A client that scanned with a
    // different one must not let this node anchor on its behalf.
    rules: rulesVersion,
    attestor: publicAttestor(key),
    stats: db.stats(),
  };
  if (chain.REGISTRY && key) {
    try {
      out.precompile = await chain.precompileAlive(key);
      out.attestorRegistered = await chain.isRegistered((await chain.wallet()).account.address);
    } catch (e) {
      out.chainError = e.shortMessage ?? e.message;
    }
  }
  return c.json(out);
});

app.get('/.well-known/jwks.json', (c) => (key ? c.json(jwks(key)) : c.json({ keys: [] })));

// ─── Free preview ─────────────────────────────────────────────────────────
app.post('/scan/free', async (c) => {
  const { content = '' } = await c.req.json().catch(() => ({}));
  if (!content) return c.json({ error: 'content required' }, 400);
  return c.json(freeScan(content));
});

// ─── Full scan -> receipt ─────────────────────────────────────────────────
app.use('/scan/*', async (c, next) => rl(c, next));
app.use('/anchor/*', async (c, next) => rl(c, next));
app.use('/receipt', async (c, next) => (c.req.method === 'POST' ? rl(c, next) : next()));
app.use('/faucet', async (c, next) => rl(c, next));
app.use('*', compress());
async function rl(c, next) {
  // nginx always sets X-Real-IP, and nothing else can reach this port (the API
  // binds loopback). A request without it is an operator tool on this machine —
  // the seeder and the survey anchor 18 tools in one go and were rate-limiting
  // themselves out. Limit the public path, not the console.
  const ip = c.req.header('x-real-ip') ?? c.req.header('x-forwarded-for')?.split(',')[0].trim();
  if (!ip) return next();
  if (limited(ip)) return c.json({ error: 'rate limited, try again in a minute' }, 429);
  return next();
}

app.post('/scan', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const { kind = 'skill', name, origin, content, manifest } = body;

  if (!name || !origin) return c.json({ error: 'name and origin required' }, 400);
  if (kind === 'mcp' && !manifest && !content) return c.json({ error: 'manifest or content required' }, 400);
  if (kind !== 'mcp' && !content) return c.json({ error: 'content required' }, 400);
  if (!key) return c.json({ error: 'no attestor key on this node — sign in the browser and POST /anchor' }, 503);

  const raw = kind === 'mcp' ? JSON.stringify(manifest ?? JSON.parse(content)) : content;
  const result = kind === 'mcp' ? scanMCP(manifest ?? JSON.parse(content), true) : scan(content);

  const tool = { id: deriveToolId({ kind, name, origin }), kind, name, origin };
  const contentHash = deriveContentHash(raw);

  const payload = buildReceipt({ tool, contentHash, result, attestorKey: key });
  const receiptHash = hashReceipt(payload);
  const jws = signReceiptJws(payload, key.privateKey);
  const receiptURI = `${BASE_URL}/receipt/${receiptHash}`;

  db.upsertTool({ tool_id: tool.id, kind, name, origin });
  db.insertScan({
    tool_id: tool.id,
    content_hash: contentHash,
    verdict: payload.verdict,
    score: result.score,
    findings_json: JSON.stringify(result.findings ?? []),
    receipt_jws: jws,
    receipt_hash: receiptHash,
    receipt_uri: receiptURI,
    created_at: payload.issued_at,
  });
  // Public scans stay off-chain. Otherwise the worker (which holds the server
  // key) would anchor anything anyone POSTs: gas drain + registry spam under
  // our attestor. Anchoring is an explicit act: operator token or own passkey.
  if (!AUTO_ANCHOR) db.setState(receiptHash, 'unanchored');

  const response = {
    tool,
    contentHash,
    verdict: payload.verdict,
    level: result.level,
    score: result.score,
    gate: payload.gate,
    rules: rulesVersion,
    findings: withFixes(result.findings ?? []),
    receipt: { hash: receiptHash, uri: receiptURI, jws },
  };

  // What the browser needs in order to sign the anchor itself.
  if (chain.REGISTRY) {
    response.anchor = {
      registry: chain.REGISTRY,
      chainId: chain.CHAIN_ID,
      pending: true,
      hint: 'sign anchorDigest(attestor, toolId, contentHash, verdict, score, receiptHash) and POST /anchor',
    };
  }

  if (AUTO_ANCHOR && chain.REGISTRY) {
    try {
      const tx = await chain.anchorScan({
        toolId: tool.id, contentHash, verdict: payload.verdict, score: result.score,
        receiptHash, receiptURI, key,
      });
      db.markAnchored(receiptHash, tx.hash, tx.block, tx.status === 'success' ? 'confirmed' : 'failed');
      response.anchor = { ...response.anchor, pending: false, tx: tx.hash, block: tx.block, attestor: tx.attestor };
    } catch (e) {
      response.anchor = { ...response.anchor, error: e.shortMessage ?? e.message };
    }
  }

  return c.json(response);
});

// ─── Anchor an existing receipt ───────────────────────────────────────────
app.post('/anchor', async (c) => {
  const { receiptHash, signature } = await c.req.json().catch(() => ({}));
  const row = db.getScan(receiptHash);
  if (!row) return c.json({ error: 'unknown receiptHash' }, 404);
  if (row.anchor_state === 'confirmed') return c.json({ ok: true, already: true, tx: row.anchor_tx });
  if (!chain.REGISTRY) return c.json({ error: 'registry address unknown — deploy first' }, 503);
  if (!signature && !key) return c.json({ error: 'signature required: this node holds no attestor key' }, 400);
  if (!signature && (!ADMIN_TOKEN || c.req.header('x-admin-token') !== ADMIN_TOKEN)) {
    return c.json({ error: 'server-key anchoring is operator-only; sign with your own attestor key instead' }, 403);
  }

  try {
    const tx = await chain.anchorScan({
      toolId: row.tool_id, contentHash: row.content_hash, verdict: row.verdict,
      score: row.score, receiptHash, receiptURI: row.receipt_uri, key, sig: signature,
    });
    db.markAnchored(receiptHash, tx.hash, tx.block, tx.status === 'success' ? 'confirmed' : 'failed');
    return c.json({ ok: tx.status === 'success', tx: tx.hash, block: tx.block, attestor: tx.attestor });
  } catch (e) {
    db.markAnchored(receiptHash, null, null, 'failed');
    return c.json({ error: e.shortMessage ?? e.message }, 502);
  }
});

/** Queue a browser-signed anchor for the batch worker instead of sending it now. */
app.post('/anchor/queue', async (c) => {
  const { receiptHash, signature } = await c.req.json().catch(() => ({}));
  if (!signature?.r || !signature?.s) return c.json({ error: 'signature {r,s} required' }, 400);
  const row = db.getScan(receiptHash);
  if (!row) return c.json({ error: 'unknown receiptHash' }, 404);
  if (row.anchor_state === 'confirmed') return c.json({ ok: true, already: true, tx: row.anchor_tx });
  db.queueScan(receiptHash, signature);
  return c.json({ ok: true, state: 'queued', note: 'the batch worker anchors this with the next batch' });
});

/** The digest a browser must sign, so the client never re-implements packing. */
app.post('/anchor/digest', async (c) => {
  const { receiptHash, attestor } = await c.req.json().catch(() => ({}));
  const row = db.getScan(receiptHash);
  if (!row) return c.json({ error: 'unknown receiptHash' }, 404);
  if (!attestor) return c.json({ error: 'attestor address required' }, 400);
  return c.json({
    digest: anchorDigest({
      chainId: chain.CHAIN_ID, registry: chain.REGISTRY, attestor,
      toolId: row.tool_id, contentHash: row.content_hash,
      verdict: row.verdict, score: row.score, receiptHash,
    }),
    fields: { toolId: row.tool_id, contentHash: row.content_hash, verdict: row.verdict, score: row.score, receiptHash },
  });
});

// ─── Receipts & registry ──────────────────────────────────────────────────
app.get('/receipt/:hash', (c) => {
  const hash = c.req.param('hash').toLowerCase();
  const jws = db.getScan(hash)?.receipt_jws ?? db.getExternalReceipt(hash)?.jws;
  if (!jws) return c.json({ error: 'not found' }, 404);
  return c.text(jws, 200, { 'content-type': 'application/jose', 'cache-control': 'public, max-age=31536000, immutable' });
});

/**
 * Publish a receipt signed by ANOTHER attestor (the browser passkey path), so its
 * on-chain receiptURI resolves. Accepted only when:
 *   - the JWS verifies against the P-256 key embedded in its own payload,
 *   - tool.id is the canonical toolId of (kind, name, origin) — no name spoofing,
 * Content-addressed and immutable; whether the attestor is trusted is decided
 * on-chain (registration + P256VERIFY on the anchor), not here.
 */
app.post('/receipt', async (c) => {
  const { jws } = await c.req.json().catch(() => ({}));
  if (typeof jws !== 'string' || jws.length > 200_000 || jws.split('.').length !== 3) return c.json({ error: 'jws required' }, 400);
  let payload;
  try { payload = decodeReceipt(jws); } catch { return c.json({ error: 'malformed receipt' }, 400); }
  const a = payload?.attestor, t = payload?.tool;
  if (!a?.x || !a?.y || !t?.id) return c.json({ error: 'receipt missing attestor or tool' }, 400);
  const pub = '0x04' + a.x.slice(2).padStart(64, '0') + a.y.slice(2).padStart(64, '0');
  let ok = false;
  try { ok = verifyReceiptJws(jws, pub); } catch {}
  if (!ok) return c.json({ error: 'signature does not verify against the embedded attestor key' }, 400);
  if (deriveToolId({ kind: t.kind, name: t.name, origin: t.origin }).toLowerCase() !== t.id.toLowerCase()) {
    return c.json({ error: 'tool.id does not match (kind, name, origin)' }, 400);
  }
  const hash = hashReceipt(payload).toLowerCase();
  db.putExternalReceipt({
    receipt_hash: hash, jws, tool_id: t.id.toLowerCase(), attestor_x: a.x, attestor_y: a.y,
    findings_json: JSON.stringify(payload.findings ?? []),
  });
  if (!db.getTool(t.id.toLowerCase())) db.upsertTool({ tool_id: t.id.toLowerCase(), kind: t.kind, name: t.name, origin: t.origin });
  return c.json({ ok: true, receiptHash: hash, uri: `${BASE_URL}/receipt/${hash}` });
});

// receiptURI on-chain is a hint; the receipt is content-addressed by its hash,
// so this node always serves it at a public URL (early anchors carry a dev URI).
const receiptURL = (hash) => (hash ? `${BASE_URL}/receipt/${hash}` : null);

const withLocal = (s) => {
  const h = s.receiptHash?.toLowerCase();
  const row = db.getScan(h);
  const ext = row ? null : db.getExternalReceipt(h);
  if (ext) return { ...s, receiptURL: receiptURL(h), findings: withFixes(JSON.parse(ext.findings_json)) };
  return { ...s, receiptURL: row ? receiptURL(s.receiptHash) : null, findings: row ? withFixes(JSON.parse(row.findings_json)) : null };
};
const toolMeta = (id) => {
  const t = db.getTool(id);
  return t ? { name: t.name, kind: t.kind, origin: t.origin } : null;
};

// toolId binds the name a server DECLARES to where it came from, so a server
// that renames itself gets a new identity — a signal worth keeping. The cost is
// that somebody holding only the package name cannot compute it: npm's
// `@modelcontextprotocol/server-memory` calls itself `memory-server`.
//
// This maps an origin to the identities this node has actually scanned. It is a
// hint from one server, not evidence: the verdict behind each candidate still
// comes from the chain, and the caller sees which name it ended up asking about.
// Registered before /registry/:toolId — Hono matches in declaration order.
app.get('/registry/resolve', (c) => {
  const origin = c.req.query('origin');
  if (!origin) return c.json({ error: 'origin required' }, 400);
  const kind = c.req.query('kind') || null;
  const rows = db.toolsByOrigin(origin.trim().replace(/\/+$/, ''), kind);
  return c.json({
    origin, kind,
    candidates: rows.map((t) => ({ toolId: t.tool_id, kind: t.kind, name: t.name, origin: t.origin, anchored: t.anchored > 0 })),
  });
});

app.get('/registry/:toolId', async (c) => {
  const toolId = c.req.param('toolId').toLowerCase();
  try {
    const { tool, scans } = await envio.toolHistory(toolId);
    if (tool) {
      return c.json({ toolId, meta: toolMeta(toolId), tool, scans: scans.map(withLocal), source: 'envio', index: envio.lastSource });
    }
  } catch (e) {
    c.header('x-envio-error', String(e.message).slice(0, 120));
  }
  // Fallback: indexer down or not caught up yet. Say so instead of pretending.
  const scans = db.scansForTool(toolId).map((s) => ({
    contentHash: s.content_hash, verdict: s.verdict, score: s.score,
    receiptHash: s.receipt_hash, receiptURI: s.receipt_uri, receiptURL: receiptURL(s.receipt_hash),
    // `timestamp` under the name the indexed path uses: a consumer falling back
    // to this one must not silently lose the age of a verdict and treat every
    // scan as undated.
    scannedAt: s.created_at, timestamp: s.created_at, txHash: s.anchor_tx, anchorState: s.anchor_state,
    findings: withFixes(JSON.parse(s.findings_json)),
  }));
  if (!scans.length) return c.json({ toolId, error: 'no scans for this tool' }, 404);
  return c.json({ toolId, meta: toolMeta(toolId), tool: null, scans, source: 'local-cache' });
});

app.get('/registry', async (c) => {
  const limit = Math.min(100, Number(c.req.query('limit') ?? 25));
  try {
    const d = await envio.tools(limit);
    return c.json({
      source: 'envio',
      index: envio.lastSource,
      graphql: process.env.PUBLIC_GRAPHQL_URL ?? 'https://graphql.monadguard.com/v1/graphql',
      cloudGraphql: process.env.ENVIO_CLOUD_GRAPHQL_URL ?? null,
      attestors: d.Attestor,
      tools: d.Tool.map((t) => ({ ...t, meta: toolMeta(t.id) })),
    });
  } catch (e) {
    return c.json({ source: 'local-cache', envioError: e.message, stats: db.stats(), tools: db.recentTools(limit) });
  }
});

// ─── JSON-RPC proxy for the passkey attestor ─────────────────────────────
// The page's CSP is connect-src 'self', and the Alchemy key must stay here.
// Read methods plus eth_sendRawTransaction (already signed in the browser).
const RPC_METHODS = new Set([
  'eth_chainId', 'eth_blockNumber', 'eth_fillTransaction', 'eth_getBalance', 'eth_getTransactionCount', 'eth_gasPrice',
  'eth_maxPriorityFeePerGas', 'eth_feeHistory', 'eth_estimateGas', 'eth_call', 'eth_getCode',
  'eth_sendRawTransaction', 'eth_getTransactionReceipt', 'eth_getTransactionByHash', 'eth_getBlockByNumber',
]);
const RPC_RATE = Number(process.env.RPC_RATE_PER_MIN ?? 240);
const rpcHits = new Map();
const clientIp = (c) => c.req.header('x-real-ip') ?? c.req.header('x-forwarded-for')?.split(',')[0].trim() ?? 'direct';
app.post('/rpc', async (c) => {
  const ip = clientIp(c), w = Math.floor(Date.now() / 60000), k = `${ip}:${w}`;
  const n = (rpcHits.get(k) ?? 0) + 1; rpcHits.set(k, n);
  if (rpcHits.size > 5000) for (const key of rpcHits.keys()) if (!key.endsWith(`:${w}`)) rpcHits.delete(key);
  if (n > RPC_RATE) return c.json({ jsonrpc: '2.0', id: null, error: { code: -32005, message: 'rate limited' } }, 429);

  const body = await c.req.json().catch(() => null);
  const calls = Array.isArray(body) ? body : [body];
  if (!body || calls.length > 20) return c.json({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'invalid request' } }, 400);
  const bad = calls.find((x) => !x || !RPC_METHODS.has(x.method));
  if (bad) return c.json({ jsonrpc: '2.0', id: bad?.id ?? null, error: { code: -32601, message: `method not allowed: ${bad?.method}` } }, 403);
  const r = await fetch(chain.RPC_URL, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(15000) })
    .catch((e) => ({ ok: false, status: 502, json: async () => ({ jsonrpc: '2.0', id: null, error: { code: -32603, message: e.message } }) }));
  return c.json(await r.json(), r.ok ? 200 : 502);
});

// ─── Testnet gas for new passkey attestors ───────────────────────────────
// One grant per address, forever; per-IP and global daily caps. Testnet only.
const FAUCET_AMOUNT = process.env.FAUCET_AMOUNT ?? '0.05';
const FAUCET_DAILY = Number(process.env.FAUCET_DAILY ?? 25);
const FAUCET_PER_IP = Number(process.env.FAUCET_PER_IP_DAILY ?? 3);
app.post('/faucet', async (c) => {
  if (chain.CHAIN_ID === 143) return c.json({ error: 'no faucet on mainnet' }, 400);
  const { address } = await c.req.json().catch(() => ({}));
  if (!address || !isAddress(address)) return c.json({ error: 'address required' }, 400);
  const to = getAddress(address);
  if (db.faucetGranted(to)) return c.json({ error: 'this address already received test gas' }, 409);
  const ip = clientIp(c), day = Math.floor(Date.now() / 1000) - 86400;
  if (db.faucetGrantsByIpSince(ip, day) >= FAUCET_PER_IP) return c.json({ error: 'daily limit for this network reached' }, 429);
  if (db.faucetGrantsSince(day) >= FAUCET_DAILY) return c.json({ error: 'faucet daily budget used up, try tomorrow or use faucet.monad.xyz' }, 429);
  const bal = await chain.publicClient.getBalance({ address: to });
  if (bal >= parseEther(FAUCET_AMOUNT) / 2n) return c.json({ ok: true, skipped: 'balance already sufficient' });
  try {
    const { client } = chain.wallet();
    const tx = await client.sendTransaction({ to, value: parseEther(FAUCET_AMOUNT) });
    db.recordFaucetGrant(to, ip, tx);
    return c.json({ ok: true, tx, amount: FAUCET_AMOUNT });
  } catch (e) {
    return c.json({ error: e.shortMessage ?? e.message }, 502);
  }
});

// ─── Survey report ───────────────────────────────────────────────────────
// capture/report.json is produced by `npm run survey` and deliberately not in
// git (it is derived data). Served read-only so the site can render it.
const REPORT = process.env.REPORT_PATH ?? new URL('../capture/report.json', import.meta.url).pathname;
app.get('/report', (c) => {
  try {
    return c.body(readFileSync(REPORT, 'utf8'), 200, { 'content-type': 'application/json', 'cache-control': 'public, max-age=300' });
  } catch {
    return c.json({ error: 'no survey has been run on this node' }, 404);
  }
});

// ─── Site ─────────────────────────────────────────────────────────────────
// One static page, served by the API itself so it shares the origin: no CORS,
// and the passkey rpId (monadguard.com) is the page's own host.
const SITE = new URL('../web/index.html', import.meta.url);
const CSP = [
  "default-src 'self'", "script-src 'self' 'unsafe-inline'", "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:", "connect-src 'self'", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'",
].join('; ');
const BUNDLE = new URL('../web/passkey.js', import.meta.url);
app.get('/passkey.js', (c) => {
  let js;
  try { js = readFileSync(BUNDLE, 'utf8'); } catch { return c.text('// passkey bundle not built: npm run build:web', 404); }
  return c.body(js, 200, { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'public, max-age=300', 'x-content-type-options': 'nosniff' });
});

app.get('/', (c) => {
  let html;
  try { html = readFileSync(SITE, 'utf8'); } catch { return c.text('site not built', 404); }
  return c.html(html, 200, {
    'content-security-policy': CSP,
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'cache-control': 'public, max-age=60',
  });
});

// Loopback only: nginx is the sole way in. Set HOST=0.0.0.0 only for local dev.
const HOST = process.env.HOST ?? '127.0.0.1';
serve({ fetch: app.fetch, port: PORT, hostname: HOST }, (i) => {
  console.log(`MonadGuard API on ${HOST}:${i.port}  chain ${chain.CHAIN_ID}  registry ${chain.REGISTRY ?? '(not deployed)'}`);
  console.log(`attestor ${key ? key.publicKeyUncompressed.slice(0, 26) + '… (' + key.source + ')' : 'none — browser-signed anchors only'}`);
});

export default app;
