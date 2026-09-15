/**
 * Attestor key material for the server process.
 *
 * IN PRODUCTION THE SERVER DOES NOT HOLD THIS KEY. PRF is a browser API:
 * the passkey ceremony happens client-side, the browser derives the P-256 key,
 * signs the digest, and posts (r, s) back. The server never sees a private key.
 *
 * This module exists for the headless path — CI, the E2E script, and the
 * fallback demo if the passkey ceremony fails on judging day. MONADGUARD_PRF_HEX
 * stands in for the 32 bytes Mera would have returned.
 */
import { deriveAttestorKey } from '../scripts/attestor.mjs';
import { hexToBytes } from '@noble/hashes/utils.js';

let cached = null;

export function loadAttestor({ allowDevKey = false } = {}) {
  if (cached) return cached;

  const hex = process.env.MONADGUARD_PRF_HEX;
  if (hex) {
    const bytes = hexToBytes(hex.replace(/^0x/, ''));
    if (bytes.length !== 32) throw new Error('MONADGUARD_PRF_HEX must be 32 bytes');
    cached = { ...deriveAttestorKey(bytes), source: 'env-prf' };
    return cached;
  }

  if (!allowDevKey) return null;

  console.warn('[keys] no MONADGUARD_PRF_HEX — using the well-known DEV key. Never anchor anything you care about with this.');
  cached = { ...deriveAttestorKey(new Uint8Array(32).fill(7)), source: 'dev-key' };
  return cached;
}

/** Public half only — safe to hand to the browser or put in a response. */
export function publicAttestor(key) {
  if (!key) return null;
  return { x: key.x, y: key.y, publicKeyUncompressed: key.publicKeyUncompressed, source: key.source };
}
