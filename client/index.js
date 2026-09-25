/**
 * monadguard — read the on-chain trust registry before an agent connects to a tool.
 *
 *   import { check, gate } from 'monadguard';
 *
 *   const r = await check({ kind: 'mcp', name: 'memory-server', origin: 'npm:@modelcontextprotocol/server-memory' });
 *   r.verdict  // 'CLEAN' | 'WARN' | 'CRITICAL' | 'UNKNOWN'
 *
 *   await gate({ kind: 'mcp', name, origin });   // throws unless someone has cleared it
 *
 * Reads Envio (indexing the ScanRegistry contract on Monad) — no key, no account,
 * nothing to trust on our side: every verdict it returns was signed by an attestor
 * and verified on-chain by the P256VERIFY precompile.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';

export const VERDICTS = ['UNKNOWN', 'CLEAN', 'WARN', 'CRITICAL'];

// Point these at your own indexer and node to run the registry yourself: the
// contract is public, so nothing here has to be ours.
export const DEFAULTS = {
  graphql: process.env.MONADGUARD_GRAPHQL ?? 'https://indexer.dev.hyperindex.xyz/4fe6364/v1/graphql',
  api: process.env.MONADGUARD_API ?? 'https://api.monadguard.com',
  timeoutMs: Number(process.env.MONADGUARD_TIMEOUT_MS ?? 6000),
};

const hex = (b) => '0x' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/** Canonical tool identity. Must match scripts/toolid.mjs in the registry repo. */
export function toolId({ kind, name, origin }) {
  const canon = `${kind}:${origin.trim().toLowerCase().replace(/\/+$/, '')}#${name.trim().toLowerCase()}`;
  return hex(keccak_256(new TextEncoder().encode(canon)));
}

/** Hash of the exact manifest text that was scanned. */
export function contentHash(manifestText) {
  return hex(keccak_256(new TextEncoder().encode(String(manifestText).replace(/\r\n/g, '\n'))));
}

async function graphql(url, query, variables, timeoutMs) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ query, variables }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const j = await r.json();
  if (j.errors) throw new Error(j.errors[0].message);
  return j.data;
}

/**
 * Identities the registry has seen under this origin.
 *
 * A hint from one server, never a verdict: whatever it returns, the verdict is
 * still read from the chain for that specific toolId.
 */
async function candidatesFor(tool, o) {
  if (!tool.origin) return [];
  const q = new URLSearchParams({ origin: tool.origin });
  if (tool.kind) q.set('kind', tool.kind);
  try {
    const r = await fetch(`${o.api}/registry/resolve?${q}`, { signal: AbortSignal.timeout(o.timeoutMs) });
    if (!r.ok) return [];
    return (await r.json()).candidates ?? [];
  } catch { return []; }
}

/**
 * Look a tool up in the registry.
 *
 * `opts.resolve` handles the gap between the name you know (the package) and
 * the name a server declares, which is the one in its identity:
 *   'auto' (default)  resolve by origin only when you gave no name — you are
 *                     asking "whatever this package is, what is known about it"
 *   true              resolve even when the name you gave missed
 *   false             no resolution, no extra request
 * When resolution is not adopted, any candidates are still reported so the
 * caller can say which name would have matched.
 *
 * @returns {{known:boolean, toolId:string, verdict:string, score:number|null,
 *            scans:number, attestors:object[], lastSeen:number|null, source:string,
 *            resolved?:object, candidates?:object[]}}
 */
export async function check(tool, opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  const named = tool.toolId != null || tool.name != null;
  const mode = o.resolve ?? 'auto';
  const adopt = mode === true || (mode === 'auto' && !named);

  if (named) {
    const r = await lookup((tool.toolId ?? toolId(tool)).toLowerCase(), o);
    if (r.known || mode === false) return r;
    // Known nothing under that name. Say what the registry does know here.
    const candidates = await candidatesFor(tool, o);
    if (!candidates.length) return r;
    if (!adopt) return { ...r, candidates };
    return adoptOne(candidates, o, r);
  }

  if (!tool.origin) throw new Error('pass {kind, name, origin}, a toolId, or at least an origin');
  if (mode === false) throw new Error('resolve:false needs a name or a toolId');
  const candidates = await candidatesFor(tool, o);
  if (!candidates.length) {
    return { known: false, toolId: null, verdict: 'UNKNOWN', score: null, scans: 0, attestors: [], lastSeen: null, candidates: [], source: 'api' };
  }
  return adoptOne(candidates, o, null);
}

/** First candidate with a verdict on chain; otherwise the first one. */
async function adoptOne(candidates, o, fallback) {
  let first = null;
  for (const c of candidates) {
    const r = await lookup(c.toolId.toLowerCase(), o);
    const hit = { ...r, resolved: { via: 'origin', name: c.name, kind: c.kind, origin: c.origin, source: o.api }, candidates };
    if (r.known) return hit;
    first ??= hit;
  }
  return first ?? fallback;
}

async function lookup(id, o) {
  const empty = { known: false, toolId: id, verdict: 'UNKNOWN', score: null, scans: 0, attestors: [], lastSeen: null };

  try {
    const d = await graphql(o.graphql, `query($id:String!){
      Tool(where:{id:{_eq:$id}}){ scanCount cleanCount warnCount criticalCount latestVerdict latestScore latestContentHash lastSeen }
      Scan(where:{tool_id:{_eq:$id}}, order_by:{blockNumber:desc}, limit:50){ attestor_id verdict score contentHash timestamp txHash }
    }`, { id }, o.timeoutMs);
    const t = d.Tool[0];
    if (!t) return { ...empty, source: 'envio' };

    // One row per attestor: its own most recent verdict. Consumers weigh attestors,
    // not raw counts — anyone may anchor, and the registry does not gatekeep that.
    const byAttestor = new Map();
    for (const s of d.Scan) if (!byAttestor.has(s.attestor_id)) byAttestor.set(s.attestor_id, s);
    const attestors = [...byAttestor.values()].map((s) => ({
      address: s.attestor_id, verdict: VERDICTS[s.verdict], score: s.score,
      contentHash: s.contentHash, timestamp: Number(s.timestamp), txHash: s.txHash,
    }));
    return {
      known: true, toolId: id,
      verdict: VERDICTS[t.latestVerdict] ?? 'UNKNOWN',
      score: t.latestScore,
      scans: t.scanCount,
      counts: { clean: t.cleanCount, warn: t.warnCount, critical: t.criticalCount },
      latestContentHash: t.latestContentHash,
      lastSeen: Number(t.lastSeen),
      attestors,
      source: 'envio',
    };
  } catch (e) {
    // Indexer unreachable: the REST mirror answers from the same chain data.
    try {
      const r = await fetch(`${o.api}/registry/${id}`, { signal: AbortSignal.timeout(o.timeoutMs) });
      if (r.status === 404) return { ...empty, source: 'api' };
      const j = await r.json();
      const scans = j.scans ?? [];
      return {
        known: scans.length > 0, toolId: id,
        verdict: VERDICTS[j.tool?.latestVerdict ?? scans[0]?.verdict ?? 0] ?? 'UNKNOWN',
        score: j.tool?.latestScore ?? scans[0]?.score ?? null,
        scans: scans.length,
        attestors: scans.map((s) => ({
          address: s.attestor_id ?? s.attestor ?? null,
          verdict: VERDICTS[s.verdict], score: s.score, contentHash: s.contentHash,
          // The cached path names it scannedAt. Reading only `timestamp` dated
          // every verdict to 1970, which the freshness check then rejected —
          // fail-closed, but it blocked everything the moment Envio blinked.
          timestamp: Number(s.timestamp ?? s.scannedAt ?? 0),
          txHash: s.txHash ?? s.anchor_tx ?? null,
        })),
        lastSeen: Number(scans[0]?.timestamp ?? scans[0]?.scannedAt ?? 0) || null,
        source: 'api',
      };
    } catch {
      throw new Error(`MonadGuard is unreachable: ${e.message}`);
    }
  }
}

export class MonadGuardBlocked extends Error {
  constructor(result, reason) {
    super(`MonadGuard blocked ${result.toolId}: ${reason}`);
    this.name = 'MonadGuardBlocked';
    this.result = result;
    this.reason = reason;
  }
}

/**
 * Throw unless the tool is safe to connect to.
 *
 * Defaults are deliberately strict: an UNKNOWN tool is not a safe tool, it is a
 * tool nobody has looked at. Loosen explicitly with `allowUnknown`.
 *
 * @param {object} tool  {kind,name,origin} or {toolId}
 * @param {object} opts  {attestors?: string[] (trust only these), maxAgeDays=90,
 *                        allowWarn=false, allowUnknown=false, contentHash?}
 */
export async function gate(tool, opts = {}) {
  const { attestors: trusted, maxAgeDays = 90, allowWarn = false, allowUnknown = false, contentHash: want } = opts;
  const r = await check(tool, opts);
  const fresh = (t) => !maxAgeDays || Date.now() / 1000 - t <= maxAgeDays * 86400;
  const pool = (trusted?.length
    ? r.attestors.filter((a) => trusted.some((t) => t.toLowerCase() === String(a.address).toLowerCase()))
    : r.attestors).filter((a) => fresh(a.timestamp) && (!want || !a.contentHash || a.contentHash.toLowerCase() === want.toLowerCase()));

  if (!r.known || pool.length === 0) {
    if (allowUnknown) return r;
    // A name you supplied is a pin, and gate() does not quietly unpin it. But
    // an unknown tool whose origin the registry knows under another name is
    // almost always that mismatch, so the error says which name would match.
    const other = !r.known && r.candidates?.length
      ? ` — the registry knows ${r.candidates[0].origin} as "${r.candidates[0].name}"; pass that name to pin it`
      : '';
    throw new MonadGuardBlocked(r, (trusted?.length ? 'no recent verdict from a trusted attestor' : 'no recent verdict on this tool') + other);
  }
  const worst = pool.find((a) => a.verdict === 'CRITICAL') ?? pool.find((a) => a.verdict === 'WARN');
  if (worst?.verdict === 'CRITICAL') throw new MonadGuardBlocked(r, `attestor ${worst.address} flagged it CRITICAL (risk ${worst.score})`);
  if (worst?.verdict === 'WARN' && !allowWarn) throw new MonadGuardBlocked(r, `attestor ${worst.address} flagged it WARN (risk ${worst.score})`);
  return r;
}
