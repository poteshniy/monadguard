/**
 * The integrator client is the only piece other teams run. Two things must hold:
 * its toolId matches the registry's byte for byte (or lookups silently miss),
 * and `gate` fails closed.
 */
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
import { toolId as canonical } from '../scripts/toolid.mjs';
import { toolId, check, gate, MonadGuardBlocked } from '../client/index.js';

const tool = { kind: 'mcp', name: 'memory-server', origin: 'npm:@modelcontextprotocol/server-memory' };
assert.equal(toolId(tool), canonical(tool), 'client toolId drifted from the registry');
assert.equal(toolId({ ...tool, name: ' Memory-Server ', origin: 'NPM:@modelcontextprotocol/server-memory/' }), canonical(tool), 'canonicalisation differs');

const now = Math.floor(Date.now() / 1000);
let reply = {};
let byId = {};        // per-toolId answers, for the resolution tests
let candidates = [];  // what /registry/resolve reports for an origin
const srv = createServer((req, res) => {
  let b = '';
  req.on('data', (d) => (b += d)).on('end', () => {
    res.setHeader('content-type', 'application/json');
    if (req.url.startsWith('/registry/resolve')) return res.end(JSON.stringify({ candidates }));
    const id = (() => { try { return JSON.parse(b).variables?.id; } catch { return null; } })();
    res.end(JSON.stringify({ data: byId[id] ?? reply }));
  });
}).listen(0);
const graphql = `http://127.0.0.1:${srv.address().port}/v1/graphql`;
const api = `http://127.0.0.1:${srv.address().port}`;
const opts = { graphql, api: 'http://127.0.0.1:1', timeoutMs: 2000 };
const scan = (verdict, attestor, age = 0, score = 0) => ({ attestor_id: attestor, verdict, score, contentHash: '0xaa', timestamp: String(now - age), txHash: '0xtx' });
const T = (latestVerdict, scans) => ({ Tool: [{ scanCount: scans.length, cleanCount: 0, warnCount: 0, criticalCount: 0, latestVerdict, latestScore: 0, latestContentHash: '0xaa', lastSeen: String(now) }], Scan: scans });

reply = { Tool: [], Scan: [] };
assert.equal((await check(tool, opts)).known, false, 'unknown tool must not look known');
await assert.rejects(() => gate(tool, opts), MonadGuardBlocked, 'unknown must fail closed');
assert.equal((await gate(tool, { ...opts, allowUnknown: true })).known, false, 'allowUnknown must pass');

reply = T(1, [scan(1, '0xa1')]);
assert.equal((await gate(tool, opts)).verdict, 'CLEAN', 'clean must pass');

reply = T(3, [scan(3, '0xa1', 0, 90)]);
await assert.rejects(() => gate(tool, opts), /CRITICAL/, 'critical must block');

reply = T(2, [scan(2, '0xa1', 0, 15)]);
await assert.rejects(() => gate(tool, opts), /WARN/, 'warn must block by default');
assert.equal((await gate(tool, { ...opts, allowWarn: true })).verdict, 'WARN', 'allowWarn must pass');

// A stale verdict is not a verdict.
reply = T(1, [scan(1, '0xa1', 200 * 86400)]);
await assert.rejects(() => gate(tool, opts), MonadGuardBlocked, 'stale clean must block');

// Pinned attestors: a stranger's CLEAN does not count.
reply = T(1, [scan(1, '0xstranger')]);
await assert.rejects(() => gate(tool, { ...opts, attestors: ['0xa1'] }), /trusted attestor/, 'untrusted attestor must not clear');
reply = T(1, [scan(1, '0xA1')]);
assert.equal((await gate(tool, { ...opts, attestors: ['0xa1'] })).verdict, 'CLEAN', 'attestor match must be case-insensitive');

// One attestor's CRITICAL outweighs another's CLEAN.
reply = T(1, [scan(1, '0xa1'), scan(3, '0xa2', 0, 95)]);
await assert.rejects(() => gate(tool, opts), /CRITICAL/, 'any critical must block');

// contentHash pinning: a clearance for another version does not transfer.
reply = T(1, [scan(1, '0xa1')]);
await assert.rejects(() => gate(tool, { ...opts, contentHash: '0xbb' }), MonadGuardBlocked, 'other version must block');

// ── Name resolution ────────────────────────────────────────────────────────
// The name inside an identity is the one the SERVER declares, not the package
// path: npm's `server-memory` calls itself `memory-server`. Guessing it from
// the path reports UNKNOWN on a tool that is in the registry.
const declared = canonical(tool);
const guessed = { kind: 'mcp', name: 'server-memory', origin: tool.origin };
const resolving = { ...opts, api };
reply = { Tool: [], Scan: [] };
byId = { [declared]: T(1, [scan(1, '0xa1')]) };
candidates = [{ toolId: declared, kind: 'mcp', name: 'memory-server', origin: tool.origin, anchored: true }];

const r1 = await check({ kind: 'mcp', origin: tool.origin }, resolving);
assert.equal(r1.known, true, 'origin alone must resolve to the declared identity');
assert.equal(r1.toolId, declared, 'resolution must land on the registry identity');
assert.equal(r1.resolved.name, 'memory-server', 'the answer must say which name it is about');

// A name the caller supplied is a pin. gate() does not quietly swap it.
const r2 = await check(guessed, resolving);
assert.equal(r2.known, false, 'a wrong name must stay unknown');
assert.equal(r2.resolved, undefined, 'must not adopt another identity behind a supplied name');
assert.equal(r2.candidates[0].name, 'memory-server', 'the miss must still report what the origin is known as');
assert.match(await gate(guessed, resolving).catch((e) => e.reason), /as "memory-server"/, 'the block must name the identity that would match');
assert.equal((await check(guessed, { ...resolving, resolve: true })).toolId, declared, 'resolve:true must adopt it');
assert.equal((await check(guessed, { ...resolving, resolve: false })).candidates, undefined, 'resolve:false must not call out at all');

// Nothing known under that origin either: still fail closed, with no identity.
candidates = [];
await assert.rejects(() => gate({ kind: 'mcp', origin: 'npm:nothing-here' }, resolving), MonadGuardBlocked, 'unresolvable origin must fail closed');

// ── The full verdict matrix ────────────────────────────────────────────────
// Reported from outside (Joe, Tanilo). Two holes, both of them fail-open:
//
//   1. An attestor can anchor UNKNOWN — "I looked, I could not tell". The gate
//      only ever threw on CRITICAL and WARN, so a pool of nothing but UNKNOWN
//      fell off the end of the function into `return r`. An undetermined tool
//      read as a cleared one, with allowUnknown:false set.
//   2. `attestors: []` is a caller saying "trust nobody" — usually because
//      their own trust list filtered down to nothing. A truthiness check reads
//      it the same as `undefined` and dropped the filter entirely, so an empty
//      trust list trusted everyone.
//
// Each row below fails on the code as shipped in 0.2.1, so they stay.
byId = {};
const id = canonical(tool);
const pinned = { ...opts, attestors: ['0xa1'], contentHash: '0xaa' };
const matrix = [
  [1, 'CLEAN', 'pass'],
  [2, 'WARN', 'block'],
  [3, 'CRITICAL', 'block'],
  [0, 'UNKNOWN', 'block'],   // ← the reported case
];
for (const [v, label, want] of matrix) {
  reply = T(v, [scan(v, '0xa1', 0, v * 30)]);
  if (want === 'pass') assert.equal((await gate(tool, pinned)).toolId, id, `${label} must pass`);
  else await assert.rejects(() => gate(tool, pinned), MonadGuardBlocked, `${label} must block`);
}

// allowUnknown is the opt-in, and it is the only thing that lets UNKNOWN clear.
reply = T(0, [scan(0, '0xa1')]);
assert.equal((await gate(tool, { ...pinned, allowUnknown: true })).verdict, 'UNKNOWN', 'allowUnknown must pass an UNKNOWN verdict');
// It is not an opt-in to anything worse: a CRITICAL attestation still blocks.
reply = T(3, [scan(3, '0xa1', 0, 95)]);
await assert.rejects(() => gate(tool, { ...pinned, allowUnknown: true }), /CRITICAL/, 'allowUnknown must not pass CRITICAL');
reply = T(2, [scan(2, '0xa1', 0, 20)]);
await assert.rejects(() => gate(tool, { ...pinned, allowUnknown: true }), /WARN/, 'allowUnknown must not pass WARN');

// CLEAN stays the only verdict that clears on its own. An UNKNOWN sitting
// beside a CLEAN does not block it — somebody did clear it.
reply = T(1, [scan(0, '0xa1'), scan(1, '0xa2')]);
assert.equal((await gate(tool, { ...opts, contentHash: '0xaa' })).verdict, 'CLEAN', 'a CLEAN alongside an UNKNOWN must still clear');

// attestors: [] — trust nobody. Nothing clears, whatever the chain says, and
// allowUnknown does not reopen it: the caller named no one who could clear it.
for (const v of [0, 1, 2, 3]) {
  reply = T(v, [scan(v, '0xa1')]);
  await assert.rejects(() => gate(tool, { ...opts, attestors: [] }), MonadGuardBlocked, `attestors:[] must block verdict ${v}`);
  await assert.rejects(() => gate(tool, { ...opts, attestors: [], allowUnknown: true }), MonadGuardBlocked, `attestors:[] must block verdict ${v} even with allowUnknown`);
  await assert.rejects(() => gate(tool, { ...opts, attestors: [], allowWarn: true }), MonadGuardBlocked, `attestors:[] must block verdict ${v} even with allowWarn`);
}

// attestors: undefined — no attestor filter. Unchanged behaviour.
reply = T(1, [scan(1, '0xanyone')]);
assert.equal((await gate(tool, { ...opts, attestors: undefined })).verdict, 'CLEAN', 'attestors:undefined must not filter');
assert.equal((await gate(tool, opts)).verdict, 'CLEAN', 'omitting attestors must not filter');

// The CLI is the README one-liner, and it builds its attestor list by reducing
// over argv — which yields `[]` when nobody passed `--attestor`. Under the rule
// above that would mean "trust nobody" and block every lookup, so the CLI has
// to send no option at all. Checked through the real binary, because the bug
// only exists in how it calls gate().
reply = T(1, [scan(1, '0xa1')]);
const cli = (args) => new Promise((done) => {
  const p = spawn(process.execPath, ['client/cli.mjs', ...args], {
    env: { ...process.env, MONADGUARD_GRAPHQL: graphql, MONADGUARD_API: api },
  });
  let out = '';
  p.stdout.on('data', (d) => (out += d));
  p.stderr.on('data', (d) => (out += d));
  p.on('close', (code) => done({ code, out }));
});
const bare = await cli(['check', tool.origin, '--name', tool.name]);
assert.equal(bare.code, 0, `the CLI must pass a CLEAN tool with no --attestor:\n${bare.out}`);
assert.match(bare.out, /CLEAN/, 'the CLI must report it CLEAN');
const wrongPin = await cli(['check', tool.origin, '--name', tool.name, '--attestor', '0xsomebody-else']);
assert.equal(wrongPin.code, 1, 'the CLI must still block when the pin does not match');

srv.close();
console.log('CLIENT OK — toolId parity, fail-closed gate, verdict matrix, empty trust list, CLI pinning, freshness, origin resolution');
