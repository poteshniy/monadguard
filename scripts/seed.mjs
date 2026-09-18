#!/usr/bin/env node
/**
 * npm run seed            dry run: scan every entry locally, print verdicts, touch nothing
 * npm run seed -- --anchor   POST /scan + /anchor for each, skipping versions already anchored
 *
 * seed/manifests.json: real tools/list captures of the official MCP reference
 * servers, plus SYNTHETIC fixtures under https://monadguard.com/fixtures.
 * Never anchor a CRITICAL verdict on a real third-party tool without reading the
 * findings first: an on-chain verdict is permanent.
 */
import '../server/env.js';
import { readFileSync } from 'node:fs';
import { scanMCP } from '../server/scanner/mcp.js';
import { scan } from '../server/scanner/engine.js';
import { toolId, contentHash } from './toolid.mjs';

const API = process.env.SEED_API_URL ?? 'http://127.0.0.1:8787';
const ANCHOR = process.argv.includes('--anchor');
const entries = JSON.parse(readFileSync(new URL('../seed/manifests.json', import.meta.url), 'utf8'));
const LEVEL = ['UNKNOWN', 'CLEAN', 'WARN', 'CRITICAL'];

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
    if (real && r.level === 'CRITICAL') { console.log(`${line}  SKIP: real tool flagged CRITICAL — review before anchoring`); continue; }
    try {
      const prev = await fetch(`${API}/registry/${id}`).then((x) => (x.ok ? x.json() : null)).catch(() => null);
      if (prev?.tool?.latestContentHash?.toLowerCase() === ch.toLowerCase()) { console.log(`${line}  already anchored`); continue; }
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
