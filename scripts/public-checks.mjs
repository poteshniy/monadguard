/**
 * Read-only checks of the PUBLIC surface, exactly as a judge sees it.
 * Never sends a mutation: an earlier probe used delete_* and it worked.
 */
import { rulesVersion } from '../server/scanner/version.js';
import { check as clientCheck } from '../client/index.js';

const API = process.env.PUBLIC_API_URL ?? 'https://api.monadguard.com';
const GQL = process.env.PUBLIC_GRAPHQL_URL ?? 'https://graphql.monadguard.com/v1/graphql';
const ORIGIN = GQL.replace(/\/v1\/graphql$/, '');

const gql = (query, headers = {}) => fetch(GQL, {
  method: 'POST',
  headers: { 'content-type': 'application/json', ...headers },
  body: JSON.stringify({ query }),
  signal: AbortSignal.timeout(8000),
}).then((r) => r.json());

export async function publicChecks() {
  const rows = [];
  const add = (state, name, detail = '') => rows.push({ state, name, detail });

  try {
    const r = await fetch(`${API}/health`, { signal: AbortSignal.timeout(8000) });
    const h = await r.json();
    r.ok && h.chainVerified && h.precompile && h.attestorRegistered
      ? add('OK', 'public api', `chain ${h.chainId} verified against the RPC — precompile + attestor ok`)
      : add('FAIL', 'public api', h.chainError ? `chain ${h.chainId}: ${h.chainError}` : `${r.status} ${JSON.stringify(h).slice(0, 140)}`);

    // The node signs with the rules it loaded at STARTUP. Fixing a rule in git
    // and forgetting to restart once put verdicts on chain that this repo
    // disagrees with. Nothing in the code can notice that from inside one
    // process — only a comparison across the two can.
    if (!h.rules) add('WARN', 'ruleset', 'this node is too old to report its ruleset');
    else if (h.rules === rulesVersion) add('OK', 'ruleset', `node and repo agree (${rulesVersion})`);
    else add('FAIL', 'ruleset', `node signs with ${h.rules}, this checkout is ${rulesVersion} — restart the API before anchoring anything`);
  } catch (e) { add('FAIL', 'public api', e.message); }

  // Hasura admin must be unreachable from outside: console 404, secret ignored.
  try {
    const c = await fetch(`${ORIGIN}/console`, { signal: AbortSignal.timeout(8000) });
    c.status === 200
      ? add('FAIL', 'hasura console', `${ORIGIN}/console is public — lock nginx to POST /v1/graphql`)
      : add('OK', 'hasura console', `closed (${c.status})`);
  } catch (e) { add('WARN', 'hasura console', e.message); }

  try {
    const r = await gql('{ __schema { mutationType { name } } }', { 'x-hasura-admin-secret': 'testing' });
    r?.data?.__schema?.mutationType
      ? add('FAIL', 'hasura admin', 'default admin secret accepted publicly — anyone can delete indexer data')
      : add('OK', 'hasura admin', 'mutations not exposed');
  } catch (e) { add('WARN', 'hasura admin', e.message); }

  try {
    const r = await gql('{ Scan { id } Tool { id } }');
    const n = r?.data?.Scan?.length ?? 0;
    if (r.errors) add('FAIL', 'public graphql', r.errors[0].message);
    else if (n === 0) add('WARN', 'public graphql', 'reachable but 0 scans — indexer reset or not caught up');
    else add('OK', 'public graphql', `${n} scans, ${r.data.Tool.length} tools`);
  } catch (e) { add('FAIL', 'public graphql', e.message); }

  const FIXED_AT = 1790073300; // 2026-09-22 10:35 UTC, BASE_URL set to the public origin
  // URIs written on-chain must be public. Anchors before 2026-09-22 carry a dev
  // URI (known, documented); any NEWER one pointing at localhost is a regression.
  try {
    const r = await gql('{ Attestor { id metaURI } Scan(order_by:{blockNumber:desc}, limit:1) { blockNumber timestamp receiptURI } }');
    const bad = (u) => /localhost|127\.0\.0\.1/.test(u ?? '');
    const last = r?.data?.Scan?.[0];
    const devAtt = (r?.data?.Attestor ?? []).filter((a) => bad(a.metaURI)).length;
    if (last && bad(last.receiptURI) && Number(last.timestamp) > FIXED_AT) {
      add('WARN', 'receipt URIs', `latest anchor (block ${last.blockNumber}) carries ${last.receiptURI.slice(0, 40)}… — check BASE_URL`);
    } else if (last && bad(last.receiptURI)) {
      add('OK', 'receipt URIs', 'only pre-fix anchors carry the dev URI (documented; served via receiptURL)');
    } else add('OK', 'receipt URIs', last ? 'latest anchor carries a public URI' : 'no scans');
    if (devAtt) add('WARN', 'attestor metaURI', `${devAtt} attestor(s) registered with a dev metaURI`);
  } catch (e) { add('WARN', 'receipt URIs', e.message); }

  // Envio Cloud: independent index, must agree with ours.
  const CLOUD = process.env.PUBLIC_ENVIO_CLOUD_URL ?? 'https://indexer.dev.hyperindex.xyz/4fe6364/v1/graphql';
  try {
    const body = JSON.stringify({ query: '{ Scan { id verdict score } }' });
    const get = (u) => fetch(u, { method: 'POST', headers: { 'content-type': 'application/json' }, body, signal: AbortSignal.timeout(8000) }).then((r) => r.json());
    const [c, s] = await Promise.all([get(CLOUD), get(GQL)]);
    const sig = (d) => (d?.data?.Scan ?? []).map((x) => `${x.id}:${x.verdict}:${x.score}`).sort().join();
    if (!c?.data) add('FAIL', 'envio cloud', `${CLOUD} not answering — redeployed? update PUBLIC_ENVIO_CLOUD_URL`);
    else if (sig(c) === sig(s)) add('OK', 'envio cloud', `${c.data.Scan.length} scans, identical to self-hosted`);
    else add('WARN', 'envio cloud', `differs from self-hosted (${c.data.Scan.length} vs ${s?.data?.Scan?.length ?? '?'}) — one is still syncing?`);
  } catch (e) { add('WARN', 'envio cloud', e.message); }

  // The site itself.
  try {
    const r = await fetch(API.replace('api.', ''), { signal: AbortSignal.timeout(8000) });
    const html = await r.text();
    r.ok && html.includes('MonadGuard')
      ? add('OK', 'site', `${API.replace('api.', '')} serves the registry page`)
      : add('FAIL', 'site', `${r.status} — page missing`);
  } catch (e) { add('FAIL', 'site', e.message); }

  // The page builds itself from these two. Serving the HTML while they answer
  // with nothing is an empty page for the visitor and a green check here.
  try {
    const d = await fetch(`${API}/registry?limit=100`, { signal: AbortSignal.timeout(8000) }).then((r) => r.json());
    const n = (d.tools ?? []).length;
    if (!n) add('FAIL', 'registry feed', `${d.source} answered with 0 tools — the page renders empty`);
    else if (d.source !== 'envio') add('WARN', 'registry feed', `${n} tools from ${d.source} — indexer down, page shows the dated snapshot`);
    else add('OK', 'registry feed', `${n} tools via ${d.index ?? 'envio'}`);
  } catch (e) { add('FAIL', 'registry feed', e.message); }

  try {
    const d = await fetch(`${API}/report`, { signal: AbortSignal.timeout(8000) }).then((r) => r.json());
    d.totals?.scanned > 0
      ? add('OK', 'survey', `${d.totals.scanned} servers, ${d.totals.tools} tool descriptions`)
      : add('FAIL', 'survey', 'no report on this node — the Survey section stays hidden');
  } catch (e) { add('FAIL', 'survey', e.message); }

  // The one-liner in the README and in every outreach message. It once answered
  // UNKNOWN on a tool that was in the registry, and nothing else would have
  // caught it: every part was healthy, the composition was not.
  try {
    const r = await clientCheck({ kind: 'mcp', origin: 'npm:@modelcontextprotocol/server-memory' }, { api: API, timeoutMs: 8000 });
    r.known && r.verdict === 'CLEAN'
      ? add('OK', 'readme one-liner', `resolves to ${r.resolved?.name ?? r.toolId.slice(0, 10)} → ${r.verdict}`)
      : add('FAIL', 'readme one-liner', `npx monadguard check npm:@modelcontextprotocol/server-memory → ${r.verdict}`);
  } catch (e) { add('FAIL', 'readme one-liner', e.message); }

  return rows;
}
