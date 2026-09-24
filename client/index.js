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

export const DEFAULTS = {
  graphql: 'https://indexer.dev.hyperindex.xyz/4fe6364/v1/graphql',
  api: 'https://api.monadguard.com',
  timeoutMs: 6000,
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
 * Look a tool up in the registry.
 * @returns {{known:boolean, toolId:string, verdict:string, score:number|null,
 *            scans:number, attestors:object[], lastSeen:number|null, source:string}}
 */
export async function check(tool, opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  const id = (tool.toolId ?? toolId(tool)).toLowerCase();
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
        attestors: scans.map((s) => ({ address: s.attestor_id ?? null, verdict: VERDICTS[s.verdict], score: s.score, timestamp: Number(s.timestamp ?? 0), txHash: s.txHash })),
        lastSeen: Number(scans[0]?.timestamp ?? 0) || null,
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
    throw new MonadGuardBlocked(r, trusted?.length ? 'no recent verdict from a trusted attestor' : 'no recent verdict on this tool');
  }
  const worst = pool.find((a) => a.verdict === 'CRITICAL') ?? pool.find((a) => a.verdict === 'WARN');
  if (worst?.verdict === 'CRITICAL') throw new MonadGuardBlocked(r, `attestor ${worst.address} flagged it CRITICAL (risk ${worst.score})`);
  if (worst?.verdict === 'WARN' && !allowWarn) throw new MonadGuardBlocked(r, `attestor ${worst.address} flagged it WARN (risk ${worst.score})`);
  return r;
}
