/**
 * Passkey attestor — one passkey, many keys (mera).
 *
 * One user-verified PRF evaluation (mera) yields 32 stable bytes. From them:
 *
 *   P-256 key      signs scan receipts + anchor digests; the contract checks it
 *                  on-chain through the P256VERIFY precompile.
 *   secp256k1 key  a mera signing session wrapped as a viem account; it is the
 *                  msg.sender that registers the P-256 key and sends anchors.
 *
 * Both are domain-separated from the same PRF output, so one fingerprint gives
 * a complete, self-sovereign attestor: no server key, no custody, no seed phrase.
 * The same passkey on another device (synced via the platform) yields the same
 * two keys — creating a SECOND passkey yields a different attestor.
 */
import { createPasskeyWithPrfOutput, getPasskeyPrfOutput, createSecp256k1SigningSession, getEvmAddress, isMeraError } from '@category-labs/mera';
import { toViemAccount } from '@category-labs/mera/viem';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { createPublicClient, createWalletClient, defineChain, http, formatEther } from 'viem';
import { SALT, deriveAttestorKey } from '../../scripts/attestor.mjs';
import { toolId as deriveToolId, contentHash as deriveContentHash } from '../../scripts/toolid.mjs';
import { scan } from '../../server/scanner/engine.js';
import { scanMCP } from '../../server/scanner/mcp.js';
import { buildReceipt, receiptHash as hashReceipt, signReceiptJws, anchorDigest, registrationDigest, signDigest } from '../../server/receipt.js';
import artifact from '../../build/ScanRegistry.json';
import deployment from '../../deployment.json';

export const RP_ID = 'monadguard.com';
const RP = { id: RP_ID, name: 'MonadGuard' };
const REGISTRY = deployment.address;
const CHAIN_ID = deployment.chainId;
const ABI = artifact.abi;
const LS_CRED = 'mg.passkey.credential';

const chain = defineChain({
  id: CHAIN_ID,
  name: CHAIN_ID === 143 ? 'Monad' : 'Monad Testnet',
  nativeCurrency: { name: 'MON', symbol: 'MON', decimals: 18 },
  // Same-origin JSON-RPC proxy: the page's CSP allows only 'self', and the
  // Alchemy key stays on the server.
  rpcUrls: { default: { http: [`${location.origin}/rpc`] } },
});
const transport = http(`${location.origin}/rpc`, { retryCount: 1 });
const pub = createPublicClient({ chain, transport, pollingInterval: 1000 });

/** secp256k1 scalar from the PRF output, domain-separated from the P-256 key. */
function deriveEvmPrivateKey(prf) {
  const n = secp256k1.CURVE.n;
  const wide = sha256(concatBytes(utf8ToBytes('MonadGuard/secp256k1/v1'), prf));
  const k = (BigInt('0x' + bytesToHex(wide)) % (n - 1n)) + 1n;
  return hexToBytes(k.toString(16).padStart(64, '0'));
}

let state = null; // { attestor (P-256), session, account, wallet, credentialId }

const remember = (credentialId) => { try { localStorage.setItem(LS_CRED, credentialId); } catch {} };
export const hasRememberedPasskey = () => { try { return !!localStorage.getItem(LS_CRED); } catch { return false; } };

function open(prf, credentialId) {
  const attestor = deriveAttestorKey(prf);
  const evmPriv = deriveEvmPrivateKey(prf);
  const session = createSecp256k1SigningSession({ privateKey: evmPriv });
  evmPriv.fill(0);
  prf.fill(0);
  const account = toViemAccount(session);
  const wallet = createWalletClient({ account, chain, transport });
  state = { attestor, session, account, wallet, credentialId, address: getEvmAddress(session.publicKey) };
  remember(credentialId);
  return summary();
}

/** Create a NEW passkey. Only ever once per person: a second one is a different attestor. */
export async function create(label) {
  const r = await createPasskeyWithPrfOutput({
    rp: RP,
    user: { name: label || 'MonadGuard attestor', displayName: label || 'MonadGuard attestor' },
    prfSalt: SALT.ATTESTOR,
  });
  return open(new Uint8Array(r.prfOutput), r.credentialId);
}

/** Use an existing passkey (this device or synced from another). */
export async function unlock() {
  const r = await getPasskeyPrfOutput({ rpId: RP_ID, prfSalt: SALT.ATTESTOR });
  return open(new Uint8Array(r.prfOutput), r.credentialId);
}

export function lock() {
  state?.session.end();
  if (state) state.attestor.privateKey.fill(0);
  state = null;
}

export function summary() {
  if (!state) return null;
  return {
    address: state.address,
    p256: { x: state.attestor.x, y: state.attestor.y },
    credentialId: state.credentialId,
  };
}

export async function status() {
  if (!state) return null;
  const [balance, registered] = await Promise.all([
    pub.getBalance({ address: state.address }),
    pub.readContract({ address: REGISTRY, abi: ABI, functionName: 'isRegistered', args: [state.address] }),
  ]);
  let keyMatches = null;
  if (registered) {
    const [x, y] = await pub.readContract({ address: REGISTRY, abi: ABI, functionName: 'attestorKey', args: [state.address] });
    keyMatches = x.toLowerCase() === state.attestor.x.toLowerCase() && y.toLowerCase() === state.attestor.y.toLowerCase();
  }
  return { ...summary(), balance: formatEther(balance), balanceWei: balance, registered, keyMatches };
}

async function send(functionName, args) {
  const hash = await state.wallet.writeContract({ address: REGISTRY, abi: ABI, functionName, args });
  const receipt = await pub.waitForTransactionReceipt({ hash, timeout: 60_000 });
  if (receipt.status !== 'success') throw new Error(`${functionName} reverted (tx ${hash})`);
  return { hash, block: Number(receipt.blockNumber) };
}

/** Bind this passkey's P-256 key to its EVM address, with proof of possession. */
export async function register() {
  if (!state) throw new Error('unlock the passkey first');
  const { attestor, address } = state;
  const digest = registrationDigest({ chainId: CHAIN_ID, registry: REGISTRY, attestor: address, x: attestor.x, y: attestor.y });
  const sig = signDigest(digest, attestor.privateKey);
  return send('registerAttestor', [attestor.x, attestor.y, `${location.origin}/#attestor/${address}`, sig.r, sig.s]);
}

/** Scan locally, sign the receipt with the passkey key, publish it, anchor it. */
export async function scanAndAnchor({ kind, name, origin, manifest, content }, onStep = () => {}) {
  if (!state) throw new Error('unlock the passkey first');
  const { attestor, address } = state;

  onStep('scan');
  const raw = kind === 'mcp' ? JSON.stringify(manifest) : content;
  const result = kind === 'mcp' ? scanMCP(manifest, true) : scan(content);
  const tool = { id: deriveToolId({ kind, name, origin }), kind, name, origin };
  const contentHash = deriveContentHash(raw);

  onStep('sign');
  const payload = buildReceipt({ tool, contentHash, result, attestorKey: attestor });
  const receiptHash = hashReceipt(payload);
  const jws = signReceiptJws(payload, attestor.privateKey);

  // Publish before anchoring so the on-chain receiptURI resolves from block one.
  // The server verifies the JWS against the key inside it and serves it by hash.
  onStep('publish');
  const up = await fetch('/receipt', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jws }) });
  const upj = await up.json().catch(() => ({}));
  if (!up.ok) throw new Error(upj.error ?? `receipt upload failed (${up.status})`);

  onStep('anchor');
  const digest = anchorDigest({ chainId: CHAIN_ID, registry: REGISTRY, attestor: address, toolId: tool.id, contentHash, verdict: payload.verdict, score: result.score, receiptHash });
  const sig = signDigest(digest, attestor.privateKey);
  const tx = await send('anchorScan', [tool.id, contentHash, payload.verdict, result.score, receiptHash, upj.uri, sig.r, sig.s]);

  return { tool, contentHash, verdict: payload.verdict, score: result.score, findings: result.findings ?? [], receiptHash, receiptURI: upj.uri, tx };
}

export async function requestGas() {
  if (!state) throw new Error('unlock the passkey first');
  const r = await fetch('/faucet', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ address: state.address }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error ?? `faucet failed (${r.status})`);
  if (j.tx) await pub.waitForTransactionReceipt({ hash: j.tx, timeout: 60_000 });
  return j;
}

export const prfSupported = async () => {
  if (!window.PublicKeyCredential) return false;
  try {
    const caps = await PublicKeyCredential.getClientCapabilities?.();
    if (caps && 'extension:prf' in caps) return !!caps['extension:prf'];
  } catch {}
  return true; // unknown: let the ceremony decide and report PRF_UNAVAILABLE
};

export const errorMessage = (e) => {
  if (isMeraError?.(e)) {
    if (e.code === 'PRF_UNAVAILABLE') return 'This passkey provider does not support the PRF extension. Use Google Password Manager (Android / Chrome) or iCloud Keychain.';
    if (e.code === 'PASSKEY_OPERATION_FAILED') return 'Passkey prompt was cancelled or failed.';
    return `${e.code}: ${e.message}`;
  }
  return e?.shortMessage ?? e?.message ?? String(e);
};

export const onDomain = () => location.hostname === RP_ID;
export const explorer = CHAIN_ID === 143 ? 'https://monadvision.com' : 'https://testnet.monadvision.com';
