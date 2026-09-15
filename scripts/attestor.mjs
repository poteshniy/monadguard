/**
 * Attestor identity, derived from a passkey PRF output.
 *
 * WHY P-256 AND NOT ED25519:
 *   Monad exposes the RIP-7212 / EIP-7951 P256VERIFY precompile at 0x100.
 *   If receipts are signed on secp256r1, ScanRegistry can VERIFY the attestor's
 *   signature on-chain instead of merely recording a hash of it. An anchor then
 *   proves authorship, not just existence. Ed25519 has no such precompile.
 *
 * WHY THIS FILE HAS NO MERA IMPORT:
 *   Mera's only job is producing 32 deterministic bytes for a given salt.
 *   Everything downstream of those 32 bytes is here and is testable today.
 *   Wiring Mera in later means replacing one function: getPrfOutput().
 */
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import canonicalize from 'canonicalize';

/** PRF salts. Each salt is an isolated namespace — never reuse one for two jobs. */
export const SALT = {
  /** signs scan receipts. NOT a wallet key, never signs a transaction. */
  ATTESTOR: sha256(utf8ToBytes('monadguard/attestor/v1')),
  /** encrypts draft findings before anchoring. Separate namespace on purpose. */
  VAULT: sha256(utf8ToBytes('monadguard/vault/v1')),
};

const N = p256.CURVE.n;

/**
 * Map 32 PRF bytes to a valid P-256 private scalar.
 * Rejection-free: reduce into [1, n-1]. Bias is ~2^-128, irrelevant here.
 */
export function deriveAttestorKey(prfOutput32) {
  if (prfOutput32?.length !== 32) throw new Error('PRF output must be 32 bytes');
  const wide = sha256(concatBytes(utf8ToBytes('MonadGuard/P256/v1'), prfOutput32));
  let k = BigInt('0x' + bytesToHex(wide)) % (N - 1n) + 1n;
  const priv = hexToBytes(k.toString(16).padStart(64, '0'));
  const point = p256.ProjectivePoint.BASE.multiply(k).toAffine();
  return {
    privateKey: priv,
    x: '0x' + point.x.toString(16).padStart(64, '0'),
    y: '0x' + point.y.toString(16).padStart(64, '0'),
    /** 0x04 || X || Y — what registerAttestor stores (as two bytes32) */
    publicKeyUncompressed: '0x04'
      + point.x.toString(16).padStart(64, '0')
      + point.y.toString(16).padStart(64, '0'),
  };
}

/** JCS-canonicalize the receipt payload and hash it. This hash is what gets signed. */
export function receiptHash(payload) {
  const canon = canonicalize(payload);
  if (canon === undefined) throw new Error('payload is not canonicalizable');
  return sha256(utf8ToBytes(canon));
}

export function signReceipt(payload, privateKey) {
  const h = receiptHash(payload);
  // lowS: the precompile accepts either, but normalising kills signature malleability.
  const sig = p256.sign(h, privateKey, { lowS: true });
  return {
    hash: '0x' + bytesToHex(h),
    r: '0x' + sig.r.toString(16).padStart(64, '0'),
    s: '0x' + sig.s.toString(16).padStart(64, '0'),
  };
}

export function verifyReceipt(payload, sig, key) {
  const h = receiptHash(payload);
  const pub = hexToBytes(key.publicKeyUncompressed.slice(2));
  return p256.verify({ r: BigInt(sig.r), s: BigInt(sig.s) }, h, pub, { lowS: true });
}

/** Exactly the 160 bytes P256VERIFY (0x100) expects: hash ‖ r ‖ s ‖ x ‖ y */
export function precompileInput(sig, key) {
  const strip = (v) => v.slice(2).padStart(64, '0');
  return '0x' + strip(sig.hash) + strip(sig.r) + strip(sig.s) + strip(key.x) + strip(key.y);
}

export const P256VERIFY = '0x0000000000000000000000000000000000000100';

/** Replace this one function with the Mera SDK call. Nothing else changes. */
export async function getPrfOutput(_salt) {
  throw new Error('browser-only: wire Mera PRF here');
}
