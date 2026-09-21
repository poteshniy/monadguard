/**
 * Read-only checks of the PUBLIC surface, exactly as a judge sees it.
 * Never sends a mutation: an earlier probe used delete_* and it worked.
 */
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
    r.ok && h.precompile && h.attestorRegistered
      ? add('OK', 'public api', `${API}/health — precompile + attestor ok`)
      : add('FAIL', 'public api', `${r.status} ${JSON.stringify(h).slice(0, 120)}`);
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

  return rows;
}
