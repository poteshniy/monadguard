/**
 * Read side. Trust history comes from Envio (indexed from the chain), not from
 * the local cache: the cache only knows scans this node produced, Envio knows
 * every anchor by every attestor. SQLite adds what the chain never stores:
 * human names and findings.
 */
const URL_ = process.env.ENVIO_GRAPHQL_URL ?? 'http://127.0.0.1:8080/v1/graphql';

async function q(query, variables = {}) {
  const r = await fetch(URL_, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ query, variables }),
    signal: AbortSignal.timeout(5000),
  });
  const j = await r.json();
  if (j.errors) throw new Error(j.errors[0].message);
  return j.data;
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
