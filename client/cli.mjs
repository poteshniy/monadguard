#!/usr/bin/env node
/**
 * monadguard check <origin> [--name <tool>] [--kind mcp|skill] [--json] [--attestor 0x…] [--max-age-days N]
 *
 * Exit code 0 when a fresh CLEAN verdict exists, 1 otherwise — so it drops into
 * CI or a pre-connect hook as a one-liner.
 */
import { check, gate, toolId, MonadGuardBlocked, VERDICTS } from './index.js';

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(`--${n}`); return i === -1 ? d : argv[i + 1]; };
const has = (n) => argv.includes(`--${n}`);
const [cmd, origin] = argv;

if (cmd !== 'check' || !origin || origin.startsWith('--')) {
  console.log(`monadguard — check a tool against the on-chain registry before connecting

  npx monadguard check npm:@modelcontextprotocol/server-memory
  npx monadguard check https://github.com/acme/skill --kind skill --name my-skill

Options
  --name <tool>        the name the server declares, if you know it. Without it
                       the registry resolves the origin to the names it has seen
  --kind mcp|skill     default: mcp
  --attestor 0x…       trust only this attestor (repeatable)
  --max-age-days N     verdict must be newer than this (default 90)
  --allow-warn         exit 0 on WARN
  --json               machine-readable output

Registry: https://monadguard.com`);
  process.exit(origin ? 1 : 0);
}

// No --name: ask the registry what this origin is known as. Guessing the name
// from the package path is worse than not guessing — npm's server-memory calls
// itself memory-server, and a wrong guess reports UNKNOWN on a scanned tool.
const tool = { kind: flag('kind', 'mcp'), origin, ...(flag('name') ? { name: flag('name') } : {}) };
const attestors = argv.reduce((a, v, i) => (v === '--attestor' ? [...a, argv[i + 1]] : a), []);
const opts = { attestors, maxAgeDays: Number(flag('max-age-days', 90)), allowWarn: has('allow-warn') };

try {
  const r = await gate(tool, opts);
  if (has('json')) console.log(JSON.stringify({ ok: true, ...r }, null, 2));
  else {
    const label = r.resolved ? `${r.resolved.name} (resolved from ${origin})` : tool.name ?? origin;
    console.log(`CLEAN  ${label}  risk ${r.score}  ${r.scans} scan(s), ${r.attestors.length} attestor(s)`);
    console.log(`       ${r.toolId}`);
    console.log(`       https://monadguard.com/#tool/${r.toolId}`);
  }
} catch (e) {
  if (e instanceof MonadGuardBlocked) {
    if (has('json')) console.log(JSON.stringify({ ok: false, reason: e.reason, ...e.result }, null, 2));
    else {
      const label = e.result.resolved ? `${e.result.resolved.name} (resolved from ${origin})` : tool.name ?? origin;
      console.log(`${e.result.verdict.padEnd(6)} ${label}  ${e.reason}`);
      if (e.result.toolId) console.log(`       ${e.result.toolId}`);
      if (e.result.known) console.log(`       https://monadguard.com/#tool/${e.result.toolId}`);
      else console.log(`       nobody has scanned this tool yet — scan it at https://monadguard.com`);
    }
    process.exit(1);
  }
  console.error(e.message);
  process.exit(2);
}
