#!/usr/bin/env node
/**
 * npm run verify:foreign -- --jwks <url> --receipt <url>
 *
 * Point our verifier at somebody else's receipt and say plainly whether it
 * checks out. Written for the Assay interop test: they verified our mainnet
 * receipts with their library, and a claim that one verifier checks both is
 * only worth making if it has been run in both directions.
 *
 * Every check is reported on its own line, pass or fail, so a failure names
 * the step that broke rather than returning a bare false. Nothing here is
 * MonadGuard-specific except the canonicalizer — which is the point: if their
 * payload is exact JCS, our JCS reproduces it byte for byte.
 *
 *   --jws-field   where the JWS lives in the response (default: jws)
 *   --expect      the receipt hash they quoted, checked against what we compute
 *   --raw         the endpoint returns a bare JWS string, not JSON
 */
import { p256 } from '@noble/curves/p256.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { canonical } from '../server/receipt.js';

const arg = (name, fallback = null) => {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : process.argv[i + 1];
};
const has = (name) => process.argv.includes(`--${name}`);

const JWKS = arg('jwks');
const RECEIPT = arg('receipt');
const FIELD = arg('jws-field', 'jws');
const EXPECT = arg('expect');
if (!JWKS || !RECEIPT) {
  console.error('usage: npm run verify:foreign -- --jwks <url> --receipt <url> [--expect 0x…] [--jws-field jws] [--raw]');
  process.exit(1);
}

let failures = 0;
const ok = (msg) => console.log(`  ok    ${msg}`);
const bad = (msg) => { failures++; console.log(`  FAIL  ${msg}`); };

const b64urlToBytes = (s) => {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
const bytesToHex = (b) => '0x' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const get = async (url, what) => {
  const r = await fetch(url, { signal: AbortSignal.timeout(15000) });
  if (!r.ok) throw new Error(`${what}: HTTP ${r.status}`);
  return r;
};

console.log(`jwks     ${JWKS}`);
console.log(`receipt  ${RECEIPT}\n`);

// ── 1. the key set ─────────────────────────────────────────────────────────
const jwks = await (await get(JWKS, 'jwks')).json();
const keys = jwks.keys ?? [];
if (!keys.length) bad('the JWKS has no keys'); else ok(`JWKS carries ${keys.length} key(s)`);

// ── 2. the receipt, and the JWS inside it ──────────────────────────────────
const res = await get(RECEIPT, 'receipt');
const body = has('raw') ? (await res.text()).trim() : null;
const doc = body === null ? await res.json() : null;
const jws = body ?? doc?.[FIELD];
if (typeof jws !== 'string' || jws.split('.').length !== 3) {
  bad(`no compact JWS in ${has('raw') ? 'the response' : `field "${FIELD}"`} — found ${typeof jws}`);
  process.exit(1);
}
ok(`got a compact JWS${doc ? ` from field "${FIELD}"` : ''}`);

const [h64, p64, s64] = jws.split('.');
const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(h64)));

// ── 3. algorithm and key id ────────────────────────────────────────────────
if (header.alg !== 'ES256') bad(`header alg is ${header.alg}, not ES256`); else ok('header alg is ES256');
const key = keys.find((k) => k.kid === header.kid) ?? (keys.length === 1 ? keys[0] : null);
if (!key) bad(`no key in the JWKS matches kid "${header.kid}"`);
else ok(`kid "${header.kid}" resolves to a key in the JWKS`);
if (key && key.crv !== 'P-256') bad(`the key curve is ${key.crv}, not P-256`);
else if (key) ok('the key is on P-256');

// ── 4. the signature itself ────────────────────────────────────────────────
if (key) {
  const pub = new Uint8Array(65);
  pub[0] = 0x04;
  pub.set(b64urlToBytes(key.x), 1);
  pub.set(b64urlToBytes(key.y), 33);
  const sig = b64urlToBytes(s64);
  const digest = sha256(new TextEncoder().encode(`${h64}.${p64}`));
  let verified = false;
  try { verified = p256.verify(sig, digest, pub); } catch (e) { bad(`signature check threw: ${e.message}`); }
  if (verified) ok('the signature verifies against their published key');
  else bad('the signature does NOT verify against their published key');
}

// ── 5. is the payload exact JCS? ───────────────────────────────────────────
// The strong claim. If their payload is canonical JSON, re-canonicalizing the
// parsed object with our implementation must reproduce the signed bytes
// exactly — any difference in key order, spacing or number form shows up here.
const payloadBytes = b64urlToBytes(p64);
const payloadText = new TextDecoder().decode(payloadBytes);
let parsed = null;
try { parsed = JSON.parse(payloadText); ok('the payload parses as JSON'); }
catch (e) { bad(`the payload is not JSON: ${e.message}`); }

if (parsed) {
  const ours = canonical(parsed);
  if (ours === payloadText) ok('the payload is byte-for-byte what our JCS produces');
  else {
    bad('the payload differs from our JCS output');
    const n = [...ours].findIndex((c, i) => c !== payloadText[i]);
    console.log(`        first difference at byte ${n}`);
    console.log(`        theirs: …${payloadText.slice(Math.max(0, n - 30), n + 30)}…`);
    console.log(`        ours:   …${ours.slice(Math.max(0, n - 30), n + 30)}…`);
  }
}

// ── 6. the hash rule ───────────────────────────────────────────────────────
const computed = bytesToHex(sha256(payloadBytes));
ok(`receiptHash = sha256(JCS(payload)) = ${computed}`);
const quoted = EXPECT ?? doc?.receiptHash ?? doc?.receipt_hash ?? null;
if (quoted) {
  if (quoted.toLowerCase() === computed.toLowerCase()) ok('it matches the hash they published');
  else bad(`it does NOT match the hash they published (${quoted})`);
} else {
  console.log('  note  no hash published alongside to compare — pass --expect <hash> to check it');
}

console.log();
if (failures) { console.log(`${failures} check(s) failed — this is what to send back, verbatim.`); process.exit(1); }
console.log('ALL CHECKS PASSED — our verifier accepts their receipt.');
