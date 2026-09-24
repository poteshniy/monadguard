/**
 * Read side. Trust history comes from Envio (indexed from the chain), not from
 * the local cache: the cache only knows scans this node produced, Envio knows
 * every anchor by every attestor. SQLite adds what the chain never stores:
 * human names and findings.
 */
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
const TIP = '{ Scan(order_by:{blockNumber:desc}, limit:1) { blockNumber } }';
const head = async (url) => Number((await ask(url, TIP, {})).Scan?.[0]?.blockNumber ?? 0);

// A silent lag is worse than an outage: the page looks fine and shows a
// registry that is missing anchors. Compare tips now and then and read from
// whichever index is further along.
let chosen = URL_, checkedAt = 0;
async function pick() {
  if (!CLOUD || Date.now() - checkedAt < 60_000) return chosen;
  checkedAt = Date.now();
  const [local, cloud] = await Promise.allSettled([head(URL_), head(CLOUD)]);
  const l = local.status === 'fulfilled' ? local.value : -1;
  const c = cloud.status === 'fulfilled' ? cloud.value : -1;
  chosen = c > l ? CLOUD : URL_;
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
    if (!other) throw e;
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
