/**
 * Cross-implementation test vectors.
 *
 * Assay (github.com/trudransh/Assay) and MonadGuard sign receipts in the same
 * envelope: an ES256 compact JWS whose payload is the RFC 8785 bytes of the
 * receipt, key at /.well-known/jwks.json, receiptHash = sha256(payload). Each
 * project pins the other's receipts and checks them on every push, so neither
 * side can change the format without the other's build going red.
 *
 * Pinned files, never a live fetch. A test that reaches across the internet
 * fails for reasons that have nothing to do with the format, and a test that
 * fails for unrelated reasons is one people learn to ignore.
 *
 * Adding a vector: drop the JSON in test/fixtures/assay/. Each file carries its
 * own jws, the jwks it verifies against, and where it came from.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { checkReceipt } from '../scripts/receipt-checks.mjs';
import { buildReceipt, signReceiptJws, jwks as jwksOf, receiptHash } from '../server/receipt.js';
import { p256 } from '@noble/curves/p256.js';

const dir = fileURLToPath(new URL('./fixtures/assay/', import.meta.url));
const files = readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
assert.ok(files.length > 0, 'no interop vectors in test/fixtures/assay — the cross-check is not running');

for (const f of files) {
  const v = JSON.parse(readFileSync(dir + f, 'utf8'));
  const { ok, checks } = checkReceipt({ jws: v.jws, jwks: v.jwks, expectHash: v.receiptHash });
  const failed = checks.filter((c) => !c.ok);
  assert.ok(ok, `${f} (${v.network ?? 'unknown network'}):\n` + failed.map((c) => `  FAIL  ${c.name}${c.detail ? ` — ${c.detail}` : ''}`).join('\n'));
  console.log(`ok   ${v.network ?? '?'}  ${v.receiptHash.slice(0, 10)}…  ${checks.length} checks`);
}

// The same checks have to reject a tampered receipt, or passing means nothing.
// Flip one byte of the payload and the signature must stop verifying.
{
  const v = JSON.parse(readFileSync(dir + files[0], 'utf8'));
  const [h, p, s] = v.jws.split('.');
  const flipped = p.slice(0, -1) + (p.at(-1) === 'A' ? 'B' : 'A');
  const { ok } = checkReceipt({ jws: `${h}.${flipped}.${s}`, jwks: v.jwks });
  assert.equal(ok, false, 'a tampered payload must not pass — the checks are not actually checking');
  console.log('ok   a tampered payload is rejected');
}

// And our own receipts must pass the same checks, so the vector format is not
// quietly special-cased for theirs.
{
  const priv = p256.utils.randomSecretKey();
  const pub = p256.getPublicKey(priv, false);
  const hex = (b) => '0x' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const key = { privateKey: priv, x: hex(pub.slice(1, 33)), y: hex(pub.slice(33, 65)) };
  const payload = buildReceipt({
    tool: { id: '0x' + '11'.repeat(32), kind: 'mcp', name: 't', origin: 'npm:x' },
    contentHash: '0x' + 'aa'.repeat(32),
    result: { scanned: true, level: 'SAFE', score: 0, findings: [], crits: 0, highs: 0, mediums: 0, lows: 0 },
    attestorKey: key, issuedAt: 1760000000,
  });
  const { ok, checks } = checkReceipt({
    jws: signReceiptJws(payload, priv), jwks: jwksOf(key), expectHash: receiptHash(payload),
  });
  assert.ok(ok, 'our own receipt must pass the interop checks:\n' + checks.filter((c) => !c.ok).map((c) => `  ${c.name} — ${c.detail}`).join('\n'));
  console.log('ok   our own receipt passes the same checks');
}

console.log(`\nINTEROP OK — ${files.length} pinned Assay receipt(s), tamper rejected, our own format passes`);
