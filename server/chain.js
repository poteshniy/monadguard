/**
 * Chain layer — Monad testnet 10143 over Alchemy RPC.
 *
 * Reads deployment.json (written by scripts/deploy.mjs) unless REGISTRY_ADDRESS
 * overrides it. Everything here is thin: build calldata, send, wait.
 */
import './env.js';
import { createPublicClient, createWalletClient, http, defineChain } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { readFileSync, existsSync } from 'node:fs';
import { anchorDigest, registrationDigest, signDigest } from './receipt.js';

const artifact = JSON.parse(readFileSync(new URL('../build/ScanRegistry.json', import.meta.url)));
export const ABI = artifact.abi;

function deployment() {
  const url = new URL('../deployment.json', import.meta.url);
  return existsSync(url) ? JSON.parse(readFileSync(url, 'utf8')) : {};
}

const dep = deployment();
export const CHAIN_ID = Number(process.env.CHAIN_ID ?? dep.chainId ?? 10143);
export const REGISTRY = process.env.REGISTRY_ADDRESS ?? dep.address ?? null;

/**
 * Alchemy is the intended transport (bounty + reliability). ALCHEMY_KEY alone
 * is enough; RPC_URL wins if set; the public endpoint is the last resort and
 * will rate-limit during a demo.
 */
export const RPC_URL = process.env.RPC_URL
  ?? (process.env.ALCHEMY_KEY
    ? `https://monad-testnet.g.alchemy.com/v2/${process.env.ALCHEMY_KEY}`
    : 'https://testnet-rpc.monad.xyz');

export const monad = defineChain({
  id: CHAIN_ID,
  name: CHAIN_ID === 143 ? 'Monad' : 'Monad Testnet',
  nativeCurrency: { name: 'MON', symbol: 'MON', decimals: 18 },
  rpcUrls: { default: { http: [RPC_URL] } },
  blockExplorers: { default: { name: 'MonadExplorer', url: CHAIN_ID === 143 ? 'https://explorer.monad.xyz' : 'https://testnet.monadexplorer.com' } },
});

export const publicClient = createPublicClient({ chain: monad, transport: http(RPC_URL) });

export function wallet() {
  const pk = process.env.PRIVATE_KEY;
  if (!pk) throw new Error('PRIVATE_KEY not set — the anchor path needs a funded account');
  const account = privateKeyToAccount(pk.startsWith('0x') ? pk : `0x${pk}`);
  return { account, client: createWalletClient({ account, chain: monad, transport: http(RPC_URL) }) };
}

const contract = (fn, args) => ({ address: REGISTRY, abi: ABI, functionName: fn, args });

export const read = (fn, args = []) => {
  if (!REGISTRY) throw new Error('REGISTRY_ADDRESS unknown — deploy first');
  return publicClient.readContract(contract(fn, args));
};

/**
 * Preflight: sign a throwaway digest locally and ask the contract to verify it.
 * If this returns false, P256VERIFY is missing or behaving differently on this
 * chain — better to learn that from a health check than from a reverted demo.
 */
export async function precompileAlive(key) {
  const digest = '0x' + '11'.repeat(32);
  const sig = signDigest(digest, key.privateKey);
  return read('verifySignature', [digest, sig.r, sig.s, key.x, key.y]);
}

export const isRegistered = (address) => read('isRegistered', [address]);

/** Bind a P-256 public key to the sending address, with proof of possession. */
export async function registerAttestor(key, metaURI = '') {
  const { account, client } = wallet();
  const digest = registrationDigest({ chainId: CHAIN_ID, registry: REGISTRY, attestor: account.address, x: key.x, y: key.y });
  const sig = signDigest(digest, key.privateKey);
  const hash = await client.writeContract(contract('registerAttestor', [key.x, key.y, metaURI, sig.r, sig.s]));
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  return { hash, block: Number(receipt.blockNumber), status: receipt.status, attestor: account.address };
}

/**
 * Anchor one scan. `sig` may come from the browser (passkey path) — pass it in
 * and the private key never touches this process. Omit it and the server signs
 * with its own key, which is the headless/CI path only.
 */
export async function anchorScan({ toolId, contentHash, verdict, score, receiptHash, receiptURI = '', key, sig }) {
  const { account, client } = wallet();
  const digest = anchorDigest({
    chainId: CHAIN_ID, registry: REGISTRY, attestor: account.address,
    toolId, contentHash, verdict, score, receiptHash,
  });
  const signature = sig ?? signDigest(digest, key.privateKey);
  const hash = await client.writeContract(
    contract('anchorScan', [toolId, contentHash, verdict, score, receiptHash, receiptURI, signature.r, signature.s]),
  );
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  return { hash, digest, block: Number(receipt.blockNumber), status: receipt.status, attestor: account.address };
}

/** Batch path: one PRF ceremony, N receipts, one transaction. */
export async function anchorScanBatch(scans) {
  const { client } = wallet();
  const hash = await client.writeContract(contract('anchorScanBatch', [scans]));
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  return { hash, block: Number(receipt.blockNumber), status: receipt.status, count: scans.length };
}

export const latestVerdict = (toolId, attestor) => read('latestVerdict', [toolId, attestor]);
export const toolScanCount = (toolId) => read('toolScanCount', [toolId]);
