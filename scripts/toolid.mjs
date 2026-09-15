// Canonical identity + content hashing. Both sides (scanner, indexer, UI)
// MUST use this, or the registry silently forks into two namespaces.
import { keccak256, toHex, stringToBytes } from 'viem';

/** Stable identity of a tool across versions. */
export function toolId({ kind, name, origin }) {
  // kind: 'mcp' | 'skill' ; origin: package name, repo url or server url
  const canon = `${kind}:${origin.trim().toLowerCase().replace(/\/+$/, '')}#${name.trim().toLowerCase()}`;
  return keccak256(stringToBytes(canon));
}

/** Hash of the exact manifest text that was scanned. */
export function contentHash(manifestText) {
  return keccak256(stringToBytes(manifestText.replace(/\r\n/g, '\n')));
}

export const VERDICT = { UNKNOWN: 0, CLEAN: 1, WARN: 2, CRITICAL: 3 };
