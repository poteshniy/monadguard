/**
 * Read side. Trust history comes from Envio (indexed from the chain), not from
 * the local cache: the cache only knows scans this node produced, Envio knows
 * every anchor by every attestor. SQLite adds what the chain never stores:
 * human names and findings.
 */
import { CHAIN_ID } from './chain.js';

const URL_ = process.env.ENVIO_GRAPHQL_URL ?? 'http://127.0.0.1:8080/v1/graphql';
const CLOUD = process.env.ENVIO_CLOUD_GRAPHQL_URL ?? null;

/** Which index answered last — the site shows it, so a fallback is visible. */
export let lastSource = 'local';

async function ask(url, query, variables) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ query, variables }),
    signal: AbortSignal.timeout(5000),
  });
  const j = await r.json();
  if (j.errors) throw new Error(j.errors[0].message);
  return j.data;
}

/**
 * Two indexes are built independently from the same contract events, so either
 * can answer. The local one has gone quiet before (HyperSync rate limits with
 * no API token); when it does, Envio Cloud keeps the page correct instead of
 * showing a stale registry that looks like the chain lost data.
 */
// An index knows which chain it indexed. Comparing raw block numbers across two
// chains is meaningless, and the failure is silent in the worst way: on the day
// this node moved to mainnet the local index was empty at block 0 while the
// cloud one still held testnet at block 66,000,000, so the "further along" index
// won and the node served another chain's registry as its own. An index on the
// wrong chain is not a fallback — it is a different registry.
const TIP = '{ chain_metadata { chain_id block_height } }';
async function head(url) {
  const rows = (await ask(url, TIP, {})).chain_metadata ?? [];
  const mine = rows.find((r) => Number(r.chain_id) === CHAIN_ID);
  return mine ? Number(mine.block_height) : null;   // null: indexes some other chain
}

let chosen = URL_, checkedAt = 0, eligible = [URL_];
async function pick() {
  if (!CLOUD || Date.now() - checkedAt < 60_000) return chosen;
  checkedAt = Date.now();
  const [local, cloud] = await Promise.allSettled([head(URL_), head(CLOUD)]);
  const at = (r) => (r.status === 'fulfilled' && r.value !== null ? r.value : -1);
  const l = at(local), c = at(cloud);
  eligible = [l >= 0 ? URL_ : null, c >= 0 ? CLOUD : null].filter(Boolean);
  chosen = c > l ? CLOUD : URL_;
  // Both unusable: keep the local one so the error comes from the index we run,
  // and /registry falls through to its own dated snapshot.
  if (!eligible.length) chosen = URL_;
  return chosen;
}

async function q(query, variables = {}) {
  const first = await pick().catch(() => URL_);
  try {
    const d = await ask(first, query, variables);
    lastSource = first === CLOUD ? 'envio-cloud' : 'local';
    return d;
  } catch (e) {
    const other = first === CLOUD ? URL_ : CLOUD;
    // Only ever fall back to an index that answered for THIS chain.
    if (!other || !eligible.includes(other)) throw e;
    const d = await ask(other, query, variables);
    lastSource = other === CLOUD ? 'envio-cloud' : 'local';
    chosen = other; checkedAt = Date.now();
    return d;
  }
}

const SCAN = 'id contentHash verdict score receiptHash receiptURI timestamp blockNumber txHash attestor_id';
const TOOL = 'id firstSeen lastSeen scanCount cleanCount warnCount criticalCount latestVerdict latestScore latestContentHash latestAttestor versionCount';

export const endpoint = URL_;

export async function toolHistory(toolId) {
  const d = await q(`query($id:String!){
    Tool(where:{id:{_eq:$id}}){ ${TOOL} }
    Scan(where:{tool_id:{_eq:$id}}, order_by:{blockNumber:desc}, limit:100){ ${SCAN} }
  }`, { id: toolId.toLowerCase() });
  return { tool: d.Tool[0] ?? null, scans: d.Scan };
}

export async function tools(limit = 25) {
  const d = await q(`query($n:Int!){
    Tool(order_by:{lastSeen:desc}, limit:$n){ ${TOOL} }
    Attestor{ id scanCount toolsCovered }
  }`, { n: limit });
  return d;
}
