/**
 * MonadGuard receipts — ES256 (secp256r1), not EdDSA.
 *
 * Two signatures come out of one key, one PRF ceremony:
 *
 *   1. RECEIPT JWS (alg ES256) over the JCS-canonicalized payload.
 *      Human/tooling-verifiable off-chain via the JWKS at /.well-known/jwks.json.
 *      This is the artifact `receiptURI` serves.
 *
 *   2. ANCHOR SIGNATURE over `anchorDigest(...)`, which is what the contract
 *      re-computes and checks through the P256VERIFY precompile.
 *
 * Why not one signature? The chain cannot re-derive sha256(JCS(payload)) from
 * calldata, so a signature over the receipt alone proves only that *some*
 * receipt was signed — it does not bind the verdict actually written on-chain.
 * The anchor digest commits to every anchored field plus (chainId, registry,
 * attestor), so a receipt cannot be replayed onto a different verdict, a
 * different deployment, or a different attestor address.
 *
 * Ported from AgentTrust `src/jws.js`, with EdDSA/Node-crypto swapped for
 * @noble/curves P-256 and the x402/mapping-doc coupling removed.
 */
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import canonicalize from 'canonicalize';
import { encodePacked } from 'viem';

export const RECEIPT_VERSION = 'monadguard/receipt/v1';
export const RULESET = 'monadguard-rules-v1 (40 skill + 10 mcp)';
export const KID = 'monadguard-p256-v1';
export const ANCHOR_DOMAIN = 'MonadGuard/anchor/v1';
export const REGISTER_DOMAIN = 'MonadGuard/register/v1';

/** On-chain verdict enum. Score carries the granularity that this loses. */
export const VERDICT = { UNKNOWN: 0, CLEAN: 1, WARN: 2, CRITICAL: 3 };

/** scanner level -> on-chain verdict */
export function toVerdict(level) {
  switch (level) {
    case 'SAFE': return VERDICT.CLEAN;
    case 'MEDIUM': return VERDICT.WARN;
    case 'HIGH': return VERDICT.WARN;
    case 'CRITICAL': return VERDICT.CRITICAL;
    default: return VERDICT.UNKNOWN;
  }
}

/** Consumer-facing gate. Anything but a clean scan halts the connection. */
export function toGate(level, score) {
  if (level === 'SAFE' && score === 0) return { gate: 'act', confidence: 0.95 };
  if (level === 'SAFE') return { gate: 'act', confidence: 0.75 };
  if (level === 'MEDIUM') return { gate: 'halt', confidence: 0.4 };
  return { gate: 'halt', confidence: 0.0 };
}

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const strip = (hex) => hex.slice(2).padStart(64, '0');

// ─────────────────────────────────────────────────────────────
// Receipt payload
// ─────────────────────────────────────────────────────────────

/**
 * Build the receipt payload. Deterministic: no uuid, no wall-clock beyond
 * `issuedAt`, so the same scan by the same attestor at the same second is
 * byte-identical. That makes `receiptHash` a real content address.
 */
export function buildReceipt({ tool, contentHash, result, attestorKey, issuedAt, ttlDays = 90 }) {
  const ts = issuedAt ?? Math.floor(Date.now() / 1000);
  const { gate, confidence } = toGate(result.level, result.score);
  return {
    version: RECEIPT_VERSION,
    ruleset: RULESET,
    issued_at: ts,
    expires_at: ts + ttlDays * 86400,
    tool: {
      id: tool.id,
      kind: tool.kind,
      name: tool.name,
      origin: tool.origin,
    },
    content_hash: contentHash,
    verdict: toVerdict(result.level),
    level: result.level,
    score: result.score,
    gate,
    confidence,
    findings: (result.findings || []).map((f) => ({
      id: f.id, cat: f.cat, sev: f.sev, desc: f.desc, line: f.line ?? null, field: f.field ?? null,
    })),
    counts: {
      critical: result.crits ?? 0,
      high: result.highs ?? 0,
      medium: result.mediums ?? 0,
      low: result.lows ?? 0,
    },
    attestor: { alg: 'ES256', crv: 'P-256', x: attestorKey.x, y: attestorKey.y },
  };
}

/** JCS-canonicalize. Every hash in this system is taken over this string. */
export function canonical(payload) {
  const canon = canonicalize(payload);
  if (canon === undefined) throw new Error('payload is not canonicalizable');
  return canon;
}

/** receiptHash = sha256(JCS(payload)) — 0x-prefixed bytes32. */
export function receiptHash(payload) {
  return '0x' + bytesToHex(sha256(utf8ToBytes(canonical(payload))));
}

// ─────────────────────────────────────────────────────────────
// JWS (ES256, compact serialization)
// ─────────────────────────────────────────────────────────────

export function signReceiptJws(payload, privateKey) {
  const header = { alg: 'ES256', kid: KID, typ: 'application/vnd.monadguard.receipt+jws', cty: 'application/json' };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(canonical(payload))}`;
  const sig = p256.sign(sha256(utf8ToBytes(signingInput)), privateKey, { lowS: true });
  return `${signingInput}.${b64url(sig.toCompactRawBytes())}`;
}

export function verifyReceiptJws(jws, pubKeyHexUncompressed) {
  const [h, p, s] = jws.split('.');
  if (!h || !p || !s) return false;
  return p256.verify(
    Buffer.from(s, 'base64url'),
    sha256(utf8ToBytes(`${h}.${p}`)),
    hexToBytes(pubKeyHexUncompressed.replace(/^0x/, '')),
    { lowS: true },
  );
}

export function decodeReceipt(jws) {
  const [, p] = jws.split('.');
  return JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
}

/** JWKS so anyone can verify a receipt without trusting our API. */
export function jwks(attestorKey) {
  return {
    keys: [{
      kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig', kid: KID,
      x: Buffer.from(strip(attestorKey.x), 'hex').toString('base64url'),
      y: Buffer.from(strip(attestorKey.y), 'hex').toString('base64url'),
    }],
  };
}

// ─────────────────────────────────────────────────────────────
// On-chain digests — MUST byte-match ScanRegistry.sol
// ─────────────────────────────────────────────────────────────

/** Mirrors ScanRegistry.anchorDigest. Parity is asserted in test/parity.test.mjs. */
export function anchorDigest({ chainId, registry, attestor, toolId, contentHash, verdict, score, receiptHash: rh }) {
  const packed = encodePacked(
    ['string', 'uint256', 'address', 'address', 'bytes32', 'bytes32', 'uint8', 'uint16', 'bytes32'],
    [ANCHOR_DOMAIN, BigInt(chainId), registry, attestor, toolId, contentHash, verdict, score, rh],
  );
  return '0x' + bytesToHex(sha256(hexToBytes(packed.slice(2))));
}

/** Mirrors ScanRegistry.registrationDigest. */
export function registrationDigest({ chainId, registry, attestor, x, y }) {
  const packed = encodePacked(
    ['string', 'uint256', 'address', 'address', 'bytes32', 'bytes32'],
    [REGISTER_DOMAIN, BigInt(chainId), registry, attestor, x, y],
  );
  return '0x' + bytesToHex(sha256(hexToBytes(packed.slice(2))));
}

/** Sign a 32-byte digest. lowS normalisation kills signature malleability. */
export function signDigest(digestHex, privateKey) {
  const sig = p256.sign(hexToBytes(digestHex.replace(/^0x/, '')), privateKey, { lowS: true });
  return {
    r: '0x' + sig.r.toString(16).padStart(64, '0'),
    s: '0x' + sig.s.toString(16).padStart(64, '0'),
  };
}

/** Exactly the 160 bytes P256VERIFY (0x100) expects: hash ‖ r ‖ s ‖ x ‖ y. */
export function precompileInput(digestHex, sig, key) {
  return '0x' + strip(digestHex) + strip(sig.r) + strip(sig.s) + strip(key.x) + strip(key.y);
}
