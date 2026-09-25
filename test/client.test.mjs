/**
 * The integrator client is the only piece other teams run. Two things must hold:
 * its toolId matches the registry's byte for byte (or lookups silently miss),
 * and `gate` fails closed.
 */
import { createServer } from 'node:http';
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

srv.close();
console.log('CLIENT OK — toolId parity, fail-closed gate, attestor pinning, freshness, origin resolution');
