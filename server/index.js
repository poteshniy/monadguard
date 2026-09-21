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
import { serve } from '@hono/node-server';
import { scan } from './scanner/engine.js';
import { scanMCP } from './scanner/mcp.js';
import { freeScan } from './free_scan.js';
import { recommend } from './recs.js';
import { buildReceipt, receiptHash as hashReceipt, signReceiptJws, jwks, anchorDigest, signDigest, toVerdict } from './receipt.js';
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
async function rl(c, next) {
  const ip = c.req.header('x-real-ip') ?? c.req.header('x-forwarded-for')?.split(',')[0].trim() ?? 'direct';
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
  const row = db.getScan(c.req.param('hash'));
  if (!row) return c.json({ error: 'not found' }, 404);
  return c.text(row.receipt_jws, 200, { 'content-type': 'application/jose' });
});

const withLocal = (s) => {
  const row = db.getScan(s.receiptHash);
  return { ...s, findings: row ? withFixes(JSON.parse(row.findings_json)) : null };
};
const toolMeta = (id) => {
  const t = db.getTool(id);
  return t ? { name: t.name, kind: t.kind, origin: t.origin } : null;
};

app.get('/registry/:toolId', async (c) => {
  const toolId = c.req.param('toolId').toLowerCase();
  try {
    const { tool, scans } = await envio.toolHistory(toolId);
    if (tool) {
      return c.json({ toolId, meta: toolMeta(toolId), tool, scans: scans.map(withLocal), source: 'envio' });
    }
  } catch (e) {
    c.header('x-envio-error', String(e.message).slice(0, 120));
  }
  // Fallback: indexer down or not caught up yet. Say so instead of pretending.
  const scans = db.scansForTool(toolId).map((s) => ({
    contentHash: s.content_hash, verdict: s.verdict, score: s.score,
    receiptHash: s.receipt_hash, receiptURI: s.receipt_uri,
    scannedAt: s.created_at, txHash: s.anchor_tx, anchorState: s.anchor_state,
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
      graphql: process.env.PUBLIC_GRAPHQL_URL ?? 'https://graphql.monadguard.com/v1/graphql',
      cloudGraphql: process.env.ENVIO_CLOUD_GRAPHQL_URL ?? null,
      attestors: d.Attestor,
      tools: d.Tool.map((t) => ({ ...t, meta: toolMeta(t.id) })),
    });
  } catch (e) {
    return c.json({ source: 'local-cache', envioError: e.message, stats: db.stats(), tools: db.recentTools(limit) });
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
