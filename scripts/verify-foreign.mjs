#!/usr/bin/env node
/**
 * node scripts/verify-foreign.mjs --jwks <url> --receipt <url> [--expect 0x…]
 *
 * Point our verifier at somebody else's live receipt and say plainly whether
 * it checks out. Written for the Assay interop test: they verified our mainnet
 * receipts with their library, and a claim that one verifier checks both is
 * only worth making if it has been run in both directions.
 *
 * The checks themselves live in receipt-checks.mjs, shared with
 * test/interop.test.mjs so the live path and the pinned path cannot drift.
 *
 *   --jws-field   where the JWS lives in the response (default: jws)
 *   --jwks-field  where the key set lives, when the receipt carries its own
 *   --raw         the endpoint returns a bare JWS string, not JSON
 */
import { checkReceipt } from './receipt-checks.mjs';

const arg = (name, fallback = null) => {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : process.argv[i + 1];
};
const has = (name) => process.argv.includes(`--${name}`);

const RECEIPT = arg('receipt');
const JWKS = arg('jwks');
const FIELD = arg('jws-field', 'jws');
const JWKS_FIELD = arg('jwks-field', 'jwks');
if (!RECEIPT || (!JWKS && has('raw'))) {
  console.error('usage: node scripts/verify-foreign.mjs --receipt <url> [--jwks <url>] [--expect 0x…] [--jws-field jws] [--raw]');
  process.exit(1);
}

const get = async (url, what) => {
  const r = await fetch(url, { signal: AbortSignal.timeout(15000) });
  if (!r.ok) throw new Error(`${what}: HTTP ${r.status}`);
  return r;
};

console.log(`receipt  ${RECEIPT}`);
if (JWKS) console.log(`jwks     ${JWKS}`);
console.log();

const res = await get(RECEIPT, 'receipt');
const doc = has('raw') ? null : await res.json();
const jws = has('raw') ? (await res.text()).trim() : doc?.[FIELD];

// Prefer the key set the receipt carries; fall back to the published endpoint.
const jwks = doc?.[JWKS_FIELD] ?? (JWKS ? await (await get(JWKS, 'jwks')).json() : null);
if (!jwks) { console.error('no JWKS: pass --jwks <url>, or the receipt must carry one'); process.exit(1); }

const expect = arg('expect') ?? doc?.receiptHash ?? doc?.receipt_hash ?? null;
const { ok, checks } = checkReceipt({ jws, jwks, expectHash: expect });

for (const c of checks) console.log(`  ${c.ok ? 'ok  ' : 'FAIL'}  ${c.name}${c.detail ? ` — ${c.detail}` : ''}`);
console.log();

if (!ok) {
  console.log(`${checks.filter((c) => !c.ok).length} check(s) failed — this is what to send back, verbatim.`);
  process.exit(1);
}
console.log(`ALL ${checks.length} CHECKS PASSED — our verifier accepts their receipt.`);
