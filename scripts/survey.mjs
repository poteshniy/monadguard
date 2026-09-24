#!/usr/bin/env node
/**
 * npm run survey            scan every captured manifest, write the report
 * npm run survey -- --anchor  also anchor the results (server key, ADMIN_TOKEN)
 *
 * Reads capture/*.json (see npm run capture), runs the scanner over each real
 * manifest and writes:
 *   capture/report.json   machine-readable
 *   capture/REPORT.md     the write-up
 *
 * Anchoring a CRITICAL verdict on somebody's real, published package is a
 * public accusation that cannot be deleted. Nothing is anchored without
 * --anchor, and --anchor still refuses CRITICAL unless it is listed in
 * capture/reviewed.json — i.e. a human read the findings and stands behind them.
 */
import '../server/env.js';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { scanMCP } from '../server/scanner/mcp.js';
import { toolId as deriveToolId, contentHash as deriveContentHash } from './toolid.mjs';

const DIR = process.env.CAPTURE_DIR ?? 'capture';
const API = process.env.SEED_API_URL ?? 'http://127.0.0.1:8787';
const ANCHOR = process.argv.includes('--anchor');
const LEVEL = { SAFE: 'CLEAN', MEDIUM: 'WARN', HIGH: 'WARN', CRITICAL: 'CRITICAL' };

const reviewed = existsSync(join(DIR, 'reviewed.json'))
  ? new Set(JSON.parse(await readFile(join(DIR, 'reviewed.json'), 'utf8')))
  : new Set();

const files = (await readdir(DIR)).filter((f) => f.endsWith('.json') && !['index.json', 'report.json', 'reviewed.json'].includes(f));
const rows = [];

for (const f of files) {
  const { name, downloads, manifest, capturedAt } = JSON.parse(await readFile(join(DIR, f), 'utf8'));
  const result = scanMCP(manifest, true);
  const row = {
    package: name, downloads: downloads ?? null, capturedAt,
    server: manifest.name, tools: manifest.tools?.length ?? 0,
    level: result.level, verdict: LEVEL[result.level] ?? 'UNKNOWN', score: result.score,
    findings: (result.findings ?? []).map((x) => ({ id: x.id, cat: x.cat, sev: x.sev, desc: x.desc, field: x.field, match: String(x.match ?? '').slice(0, 160) })),
    toolId: deriveToolId({ kind: 'mcp', name: manifest.name, origin: `npm:${name}` }),
    contentHash: deriveContentHash(JSON.stringify(manifest)),
  };
  rows.push(row);
  console.log(`${row.verdict.padEnd(8)} ${String(row.score).padStart(3)}  ${name.padEnd(44)} ${row.tools} tools  ${[...new Set(row.findings.map((x) => x.id))].join(',') || '-'}`);
}

rows.sort((a, b) => b.score - a.score || (b.downloads ?? 0) - (a.downloads ?? 0));

// What could not be inspected at all is part of the picture: most of those
// servers want an API key before they will answer a handshake.
let coverage = { attempted: rows.length, unprobeable: 0, failed: 0 };
if (existsSync(join(DIR, 'index.json'))) {
  const idx = JSON.parse(await readFile(join(DIR, 'index.json'), 'utf8'));
  coverage = {
    attempted: idx.length,
    captured: idx.filter((x) => x.status === 'ok').length,
    unprobeable: idx.filter((x) => x.status === 'unprobeable').length,
    failed: idx.filter((x) => x.status === 'failed').length,
  };
}

const byRule = {};
for (const r of rows) for (const id of new Set(r.findings.map((f) => f.id))) (byRule[id] ??= { id, desc: r.findings.find((f) => f.id === id).desc, packages: [] }).packages.push(r.package);
const totals = {
  scanned: rows.length,
  tools: rows.reduce((n, r) => n + r.tools, 0),
  clean: rows.filter((r) => r.verdict === 'CLEAN').length,
  warn: rows.filter((r) => r.verdict === 'WARN').length,
  critical: rows.filter((r) => r.verdict === 'CRITICAL').length,
  reach: rows.reduce((n, r) => n + (r.downloads ?? 0), 0),
};

// Injection-class rules are the ones that would mean "someone is attacking you".
const ATTACK_CATS = new Set(['mcp_poisoning', 'mcp_rug_pull', 'mcp_exfiltration', 'injection', 'exfiltration', 'backdoor', 'credentials']);
const attackHits = rows.flatMap((r) => r.findings.filter((f) => ATTACK_CATS.has(f.cat) && f.sev >= 70).map((f) => ({ package: r.package, ...f })));
const byCat = {};
for (const r of rows) for (const f of r.findings) (byCat[f.cat] ??= new Set()).add(r.package);

await writeFile(join(DIR, 'report.json'), JSON.stringify({ generatedAt: new Date().toISOString(), totals, coverage, byRule, byCat: Object.fromEntries(Object.entries(byCat).map(([k, v]) => [k, [...v]])), attackHits, rows }, null, 1));

const md = `# State of MCP security — ${new Date().toISOString().slice(0, 10)}

${totals.scanned} MCP servers published on npm, captured by running each one in a sandbox and
asking it for its real \`tools/list\`, then scanned with the MonadGuard ruleset
(40 skill rules + 10 MCP rules). Together they account for ~${(totals.reach / 1e6).toFixed(1)}M downloads a month.

| verdict | servers |
|---|---|
| CLEAN | ${totals.clean} |
| WARN | ${totals.warn} |
| CRITICAL | ${totals.critical} |

Total tool descriptions inspected: ${totals.tools}.

## ${attackHits.length === 0 ? 'The headline: nothing was attacking anyone' : 'Injection-class hits — read before concluding anything'}

${attackHits.length === 0
  ? `**Not one injection-class pattern fired** — no hidden instructions, no "ignore previous
instructions", no exfiltration wording, no rug-pull update hooks — across ${totals.tools} tool
descriptions from ${totals.scanned} published servers. The same ruleset catches all three of our
synthetic attack fixtures, so the rules are not simply asleep.

That is the useful result. The risk in the MCP ecosystem today is not that popular published
servers are poisoned; it is that **nothing checks the ones that are not popular**, and that a
server can change its manifest after you trust it. Both are what a registry of anchored,
content-hash-pinned verdicts is for.`
  : `${attackHits.length} injection-class hit(s) need a human read before any conclusion:\n\n${attackHits.map((h) => `- \`${h.package}\` — ${h.id} ${h.desc} (${h.field})`).join('\n')}`}

## Coverage

| | servers |
|---|---|
| captured and scanned | ${coverage.captured ?? totals.scanned} |
| could not be probed (handshake hangs without credentials) | ${coverage.unprobeable} |
| failed to install or run | ${coverage.failed} |

Roughly ${Math.round(100 * (coverage.unprobeable + coverage.failed) / Math.max(1, coverage.attempted))}% of the most-downloaded MCP servers cannot be inspected at all without
handing them an API key first. A user installing one has even less visibility than this survey did.

## Capabilities the tools ask for

| category | servers |
|---|---|
${Object.entries(byCat).sort((a, b) => b[1].size - a[1].size).map(([c, v]) => `| ${c} | ${v.size} |`).join('\n')}

## What fired, and how often

| rule | what it catches | servers |
|---|---|---|
${Object.values(byRule).sort((a, b) => b.packages.length - a.packages.length).map((r) => `| \`${r.id}\` | ${r.desc} | ${r.packages.length} |`).join('\n')}

## Per server

| server | monthly downloads | tools | verdict | risk | rules |
|---|---|---|---|---|---|
${rows.map((r) => `| \`${r.package}\` | ${(r.downloads ?? 0).toLocaleString('en-US')} | ${r.tools} | ${r.verdict} | ${r.score} | ${[...new Set(r.findings.map((f) => f.id))].join(', ') || '—'} |`).join('\n')}

## Method, and what this is not

Each server was installed with \`--ignore-scripts\` and probed in a container with no network.
Only its declared interface — tool names, descriptions, input schemas, resources, prompts — was
examined. **Nothing here is a claim that a package is malicious.** These rules catch patterns
that make prompt injection and tool poisoning possible; most hits are careless wording, not
attacks. A CLEAN verdict is not a guarantee either: this is static analysis of a manifest, and
the code behind the manifest was never executed.

Verdicts anchored on Monad testnet are listed at https://monadguard.com — with the receipt and
the findings behind each one, signed and verifiable.
`;
await writeFile(join(DIR, 'REPORT.md'), md);
console.log(`\n${totals.scanned} scanned: ${totals.clean} clean, ${totals.warn} warn, ${totals.critical} critical -> ${DIR}/REPORT.md`);

if (!ANCHOR) { console.log('dry run. anchor with: npm run survey -- --anchor'); process.exit(0); }

let failed = 0;
for (const r of rows) {
  if (r.verdict === 'CRITICAL' && !reviewed.has(r.package)) {
    console.log(`SKIP ${r.package}: CRITICAL and not in ${DIR}/reviewed.json — read the findings first`);
    continue;
  }
  const { manifest } = JSON.parse(await readFile(join(DIR, files.find((f) => f.startsWith(r.package.replace(/[@/]/g, '_')))), 'utf8'));
  try {
    const prev = await fetch(`${API}/registry/${r.toolId}`).then((x) => (x.ok ? x.json() : null)).catch(() => null);
    if (prev?.tool?.latestContentHash?.toLowerCase() === r.contentHash.toLowerCase()) { console.log(`= ${r.package} already anchored`); continue; }
    const s = await fetch(`${API}/scan`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ kind: 'mcp', name: manifest.name, origin: `npm:${r.package}`, manifest }),
    }).then((x) => x.json());
    if (s.error) throw new Error(s.error);
    const a = await fetch(`${API}/anchor`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-admin-token': process.env.ADMIN_TOKEN ?? '' },
      body: JSON.stringify({ receiptHash: s.receipt.hash }),
    }).then((x) => x.json());
    if (!a.ok && !a.already) throw new Error(a.error ?? 'anchor failed');
    console.log(`+ ${r.package} -> ${r.verdict} tx ${a.tx}`);
  } catch (e) { failed++; console.log(`! ${r.package}: ${e.message}`); }
}
process.exit(failed ? 1 : 0);
