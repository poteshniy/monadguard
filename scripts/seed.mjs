#!/usr/bin/env node
/**
 * npm run seed                          dry run: scan every entry locally, print verdicts, touch nothing
 * npm run seed -- --anchor              anchor the SYNTHETIC fixtures only
 * npm run seed -- --anchor --include-real  also anchor the real captures in this file
 *
 * seed/manifests.json holds two different things: SYNTHETIC fixtures under
 * https://monadguard.com/fixtures, which exist to prove the ruleset still
 * catches attacks, and older real `tools/list` captures of the official MCP
 * reference servers.
 *
 * Only the fixtures are anchored by default. The real captures are older
 * snapshots of servers the survey already covers from `capture/`, so anchoring
 * them adds a second, OLDER manifest version to a tool that already has a
 * current one — costing gas and making the newest anchor the stale one. That
 * happened once on mainnet; hence the flag.
 *
 * Never anchor a CRITICAL verdict on a real third-party tool without reading the
 * findings first: an on-chain verdict is permanent.
 */
import '../server/env.js';
import { readFileSync } from 'node:fs';
import { scanMCP } from '../server/scanner/mcp.js';
import { scan } from '../server/scanner/engine.js';
import { rulesVersion } from '../server/scanner/version.js';
import { toolId, contentHash, VERDICT } from './toolid.mjs';

const API = process.env.SEED_API_URL ?? 'http://127.0.0.1:8787';
const ANCHOR = process.argv.includes('--anchor');
const INCLUDE_REAL = process.argv.includes('--include-real');
const entries = JSON.parse(readFileSync(new URL('../seed/manifests.json', import.meta.url), 'utf8'));
const LEVEL = ['UNKNOWN', 'CLEAN', 'WARN', 'CRITICAL'];
const LEVEL_TO_VERDICT = { SAFE: 'CLEAN', MEDIUM: 'WARN', HIGH: 'WARN', CRITICAL: 'CRITICAL' };

// The API signs with the rules it loaded at startup, not the ones in this
// checkout. Anchoring through it without checking put verdicts on chain once
// that this repository disagreed with.
if (ANCHOR) {
  const h = await fetch(`${API}/health`).then((r) => r.json()).catch((e) => ({ error: e.message }));
  if (h.error) { console.error(`cannot reach ${API}: ${h.error}`); process.exit(1); }
  if (h.rules !== rulesVersion) {
    console.error(`ruleset mismatch — refusing to anchor.
  this checkout: ${rulesVersion}
  the API:       ${h.rules ?? '(too old to say)'}
Restart it and run this again:  pm2 restart monadguard-api --update-env`);
    process.exit(1);
  }
  console.log(`anchoring on chain ${h.chainId}${INCLUDE_REAL ? ' — INCLUDING the real captures' : ' — fixtures only'}\n`);
}

let failed = 0;
for (const e of entries) {
  const id = toolId(e);
  const raw = e.kind === 'mcp' ? JSON.stringify(e.manifest) : e.content;
  const ch = contentHash(raw);
  const r = e.kind === 'mcp' ? scanMCP(e.manifest, true) : scan(e.content);
  const ids = [...new Set((r.findings ?? []).map((f) => f.id))].join(',') || '-';
  const real = !e.origin.includes('/fixtures');
  let line = `${r.level.padEnd(8)} ${String(r.score).padStart(3)}  ${e.name.padEnd(32)} ${ids}`;

  if (ANCHOR) {
    if (real && !INCLUDE_REAL) { console.log(`${line}  skipped: real capture, anchor it with --include-real`); continue; }
    if (real && r.level === 'CRITICAL') { console.log(`${line}  SKIP: real tool flagged CRITICAL — review before anchoring`); continue; }
    try {
      const prev = await fetch(`${API}/registry/${id}`).then((x) => (x.ok ? x.json() : null)).catch(() => null);
      // Same manifest AND same verdict is already anchored. The same manifest
      // scored differently is a correction, and belongs on chain.
      if (prev?.tool?.latestContentHash?.toLowerCase() === ch.toLowerCase()
        && Number(prev.tool.latestVerdict) === VERDICT[LEVEL_TO_VERDICT[r.level]]) {
        console.log(`${line}  already anchored`);
        continue;
      }
      const s = await fetch(`${API}/scan`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ kind: e.kind, name: e.name, origin: e.origin, manifest: e.manifest, content: e.content }),
      }).then((x) => x.json());
      if (s.error) throw new Error(s.error);
      let tx = s.anchor?.tx;
      if (!tx) {
        const a = await fetch(`${API}/anchor`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-admin-token': process.env.ADMIN_TOKEN ?? '' },
          body: JSON.stringify({ receiptHash: s.receipt.hash }),
        }).then((x) => x.json());
        if (!a.ok && !a.already) throw new Error(a.error ?? 'anchor failed');
        tx = a.tx;
      }
      line += `  -> ${LEVEL[s.verdict]} tx ${tx}`;
    } catch (err) { failed++; line += `  FAIL ${err.message}`; }
  }
  console.log(line);
}
if (!ANCHOR) console.log('\ndry run. anchor with: npm run seed -- --anchor');
process.exit(failed ? 1 : 0);
