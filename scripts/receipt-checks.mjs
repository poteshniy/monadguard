/**
 * The interop checks, with no I/O.
 *
 * Two callers share this on purpose: `verify-foreign.mjs` fetches a receipt
 * over the network and runs them, and `test/interop.test.mjs` runs them against
 * receipts pinned in this repo. If the two had their own copies they would
 * drift, and the test would stop testing the thing the script does — which is
 * the exact failure we have been fixing in this codebase all week.
 *
 * Nothing here is MonadGuard-specific except the canonicalizer, which is the
 * point: a receipt from another implementation passes check 8 only if their
 * JCS and ours produce the same bytes.
 */
import { p256 } from '@noble/curves/p256.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { canonical } from '../server/receipt.js';

const b64urlToBytes = (s) => {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(String(s).replace(/-/g, '+').replace(/_/g, '/') + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
const toHex = (b) => '0x' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/**
 * @param {object} input {jws: compact JWS, jwks: {keys:[…]}, expectHash?: '0x…'}
 * @returns {{ok:boolean, hash:string|null, checks:{name:string, ok:boolean, detail?:string}[]}}
 */
export function checkReceipt({ jws, jwks, expectHash = null }) {
  const checks = [];
  const add = (name, ok, detail) => { checks.push(detail === undefined ? { name, ok } : { name, ok, detail }); return ok; };
  const done = () => ({ ok: checks.every((c) => c.ok), hash, checks });
  let hash = null;

  const keys = jwks?.keys ?? [];
  add('the JWKS carries at least one key', keys.length > 0, `${keys.length} key(s)`);

  const parts = typeof jws === 'string' ? jws.split('.') : [];
  if (!add('the JWS is compact serialization', parts.length === 3, `${parts.length} part(s)`)) return done();
  const [h64, p64, s64] = parts;

  let header;
  try { header = JSON.parse(new TextDecoder().decode(b64urlToBytes(h64))); }
  catch (e) { add('the JWS header parses', false, e.message); return done(); }

  add('the header alg is ES256', header.alg === 'ES256', String(header.alg));

  const key = keys.find((k) => k.kid === header.kid) ?? (keys.length === 1 ? keys[0] : null);
  add('the kid resolves to a key in the JWKS', !!key, header.kid ? `kid ${header.kid}` : 'no kid in the header');
  if (key) add('the key is on P-256', key.crv === 'P-256', String(key.crv));

  // The signature, over exactly the bytes a JWS verifier signs: "<header>.<payload>".
  if (key && key.crv === 'P-256') {
    let verified = false, detail;
    try {
      const pub = new Uint8Array(65);
      pub[0] = 0x04;
      pub.set(b64urlToBytes(key.x), 1);
      pub.set(b64urlToBytes(key.y), 33);
      verified = p256.verify(b64urlToBytes(s64), sha256(new TextEncoder().encode(`${h64}.${p64}`)), pub);
    } catch (e) { detail = e.message; }
    add('the signature verifies against the published key', verified, detail);
  }

  const payloadBytes = b64urlToBytes(p64);
  const payloadText = new TextDecoder().decode(payloadBytes);
  let parsed = null;
  try { parsed = JSON.parse(payloadText); add('the payload parses as JSON', true); }
  catch (e) { add('the payload parses as JSON', false, e.message); }

  // The check that makes this a format rather than two teams using the same
  // three letters: re-canonicalizing their parsed payload with our JCS has to
  // reproduce the signed bytes exactly, not merely equivalent JSON.
  if (parsed !== null) {
    const ours = canonical(parsed);
    if (ours === payloadText) add('the payload is byte-for-byte what our JCS produces', true);
    else {
      const n = [...ours].findIndex((c, i) => c !== payloadText[i]);
      const slice = (s) => s.slice(Math.max(0, n - 30), n + 30);
      add('the payload is byte-for-byte what our JCS produces', false,
        `first difference at byte ${n}\n      theirs: …${slice(payloadText)}…\n      ours:   …${slice(ours)}…`);
    }
  }

  hash = toHex(sha256(payloadBytes));
  add('receiptHash = sha256(JCS(payload))', true, hash);
  if (expectHash) {
    add('it matches the published hash', String(expectHash).toLowerCase() === hash.toLowerCase(), `published ${expectHash}`);
  }

  return done();
}
