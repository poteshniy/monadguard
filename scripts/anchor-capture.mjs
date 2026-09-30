#!/usr/bin/env node
/**
 * npm run anchor:capture -- capture/remote/host_mcp.json        scan and print
 * npm run anchor:capture -- capture/remote/host_mcp.json --anchor   and anchor it
 *
 * One captured manifest, scanned and anchored under the identity the capture
 * carries. The survey is for the npm sweep and the seeder for the fixtures;
 * this is the path for a server somebody sent us — which is how most of them
 * will arrive from here on.
 *
 * Refuses to anchor a CRITICAL verdict on somebody else's real server unless
 * they are listed in capture/reviewed.json. An on-chain CRITICAL is a public
 * accusation that cannot be edited afterwards, so a human reads the findings
 * and decides, every time.
 */
import '../server/env.js';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { scanMCP } from '../server/scanner/mcp.js';
import { rulesVersion } from '../server/scanner/version.js';
import { toolId as deriveToolId, contentHash as deriveContentHash, VERDICT } from './toolid.mjs';

const API = process.env.SEED_API_URL ?? 'http://127.0.0.1:8787';
const argv = process.argv.slice(2);
const ANCHOR = argv.includes('--anchor');
const file = argv.find((a) => !a.startsWith('--'));
if (!file) { console.error('usage: npm run anchor:capture -- <capture file> [--anchor]'); process.exit(1); }

const LEVEL = { SAFE: 'CLEAN', MEDIUM: 'WARN', HIGH: 'WARN', CRITICAL: 'CRITICAL' };
const NAME = ['UNKNOWN', 'CLEAN', 'WARN', 'CRITICAL'];

const cap = JSON.parse(await readFile(file, 'utf8'));
const manifest = cap.manifest;
if (!manifest) { console.error(`${file} has no manifest`); process.exit(1); }

// The identity is what the capture recorded: a hosted server's origin is its
// endpoint, and the name is the one the server declares about itself.
const name = manifest.name ?? cap.name;
const origin = cap.origin ?? (cap.url ? `mcp:${String(cap.url).replace(/\/+$/, '')}` : null);
if (!origin) { console.error(`${file} has neither origin nor url — cannot form an identity`); process.exit(1); }

const result = scanMCP(manifest, true);
const verdict = LEVEL[result.level] ?? 'UNKNOWN';
const id = deriveToolId({ kind: 'mcp', name, origin });
const ch = deriveContentHash(JSON.stringify(manifest));

console.log(`${name}  ${origin}`);
console.log(`  toolId      ${id}`);
console.log(`  contentHash ${ch}`);
console.log(`  verdict     ${verdict}  risk ${result.score}  ${manifest.tools?.length ?? 0} tool(s)`);
for (const f of result.findings ?? []) console.log(`    ${f.id} ${f.cat} — ${String(f.desc).slice(0, 80)} (${f.field})`);

if (!ANCHOR) { console.log('\ndry run. anchor with --anchor'); process.exit(0); }

const reviewed = existsSync('capture/reviewed.json')
  ? new Set(JSON.parse(await readFile('capture/reviewed.json', 'utf8'))) : new Set();
if (verdict === 'CRITICAL' && !reviewed.has(origin) && !reviewed.has(name)) {
  console.error(`\nCRITICAL on somebody else's server. Read the findings, talk to them, then add
"${origin}" to capture/reviewed.json if it still stands. Not anchoring.`);
  process.exit(1);
}

const h = await fetch(`${API}/health`).then((r) => r.json()).catch((e) => ({ error: e.message }));
if (h.error) { console.error(`cannot reach ${API}: ${h.error}`); process.exit(1); }
if (h.rules !== rulesVersion) {
  console.error(`ruleset mismatch — refusing to anchor.
  this checkout: ${rulesVersion}
  the API:       ${h.rules ?? '(too old to say)'}
Restart it and run this again:  pm2 restart monadguard-api --update-env`);
  process.exit(1);
}

const prev = await fetch(`${API}/registry/${id}`).then((x) => (x.ok ? x.json() : null)).catch(() => null);
if (prev?.tool?.latestContentHash?.toLowerCase() === ch.toLowerCase()
  && Number(prev.tool.latestVerdict) === VERDICT[verdict]) {
  console.log('\nalready anchored with this verdict');
  process.exit(0);
}

const s = await fetch(`${API}/scan`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ kind: 'mcp', name, origin, manifest }),
}).then((x) => x.json());
if (s.error) { console.error(s.error); process.exit(1); }
if (s.rules !== rulesVersion) { console.error(`the API switched rulesets mid-run (${s.rules})`); process.exit(1); }
if (s.verdict !== VERDICT[verdict] || s.score !== result.score) {
  console.error(`the API scanned it as ${NAME[s.verdict]} ${s.score}, this checkout says ${verdict} ${result.score} — not anchoring`);
  process.exit(1);
}

const a = await fetch(`${API}/anchor`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-admin-token': process.env.ADMIN_TOKEN ?? '' },
  body: JSON.stringify({ receiptHash: s.receipt.hash }),
}).then((x) => x.json());
if (!a.ok && !a.already) { console.error(a.error ?? 'anchor failed'); process.exit(1); }
console.log(`\nanchored on chain ${h.chainId}: ${verdict}  tx ${a.tx}`);
console.log(`https://monadguard.com/#tool/${id}`);
