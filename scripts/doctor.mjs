#!/usr/bin/env node
/**
 * npm run doctor — everything that can be wrong, checked in one pass.
 *
 * The point is ordering: each check tells you whether the next one is even
 * meaningful. A failed RPC makes the balance check noise, a missing precompile
 * makes the whole project noise. Without this you find these out one at a time,
 * from four different commands, each with a different error style.
 *
 * Exit 0 = ready to deploy/run. Exit 1 = something is FAIL.
 * WARN never fails the run — it flags things that only matter later.
 */
import { existsSync, readFileSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { createPublicClient, http, defineChain } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

const root = new URL('..', import.meta.url).pathname;
const rows = [];
let failed = 0;

const add = (state, name, detail = '') => {
  rows.push({ state, name, detail });
  if (state === 'FAIL') failed++;
};
const ok = (n, d) => add('OK', n, d);
const warn = (n, d) => add('WARN', n, d);
const fail = (n, d) => add('FAIL', n, d);

// ── .env is loaded by hand: no dotenv dependency for one file ──────────────
const envPath = `${root}/.env`;
if (existsSync(envPath)) {
  for (const line of readFileSync(envPath, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
}

// ── 1. Runtime ────────────────────────────────────────────────────────────
const major = Number(process.versions.node.split('.')[0]);
major >= 20
  ? ok('node', `v${process.versions.node}`)
  : fail('node', `v${process.versions.node} — need 20+ (ESM + native fetch)`);

try {
  const { default: Database } = await import('better-sqlite3');
  new Database(':memory:').close();
  ok('better-sqlite3', 'native module loads');
} catch (e) {
  fail('better-sqlite3', `${e.message.split('\n')[0]} — try: apt install build-essential python3 && npm rebuild`);
}

// ── 2. Build artifact ─────────────────────────────────────────────────────
let artifact = null;
if (existsSync(`${root}/build/ScanRegistry.json`)) {
  artifact = JSON.parse(readFileSync(`${root}/build/ScanRegistry.json`, 'utf8'));
  const hasP256 = artifact.abi.some((f) => f.name === 'anchorDigest');
  hasP256
    ? ok('build/ScanRegistry.json', `${(artifact.bytecode.length - 2) / 2} bytes, P256 ABI`)
    : fail('build/ScanRegistry.json', 'stale — predates the P256VERIFY rewrite. run: npm run compile');
} else {
  fail('build/ScanRegistry.json', 'missing — run: npm run compile');
}

// ── 3. Environment ────────────────────────────────────────────────────────
existsSync(envPath) ? ok('.env', 'present') : warn('.env', 'missing — using process env only');

const CHAIN_ID = Number(process.env.CHAIN_ID ?? 10143);
const prf = process.env.MONADGUARD_PRF_HEX;
if (!prf) {
  warn('MONADGUARD_PRF_HEX', 'unset — dev key in development, hard failure under NODE_ENV=production');
} else if (!/^(0x)?[0-9a-fA-F]{64}$/.test(prf)) {
  fail('MONADGUARD_PRF_HEX', 'not 32 hex bytes — regenerate: openssl rand -hex 32');
} else if (/^(0?7)+$/.test(prf.replace(/^0x/, ''))) {
  fail('MONADGUARD_PRF_HEX', 'this is the well-known dev seed — anyone can forge your receipts');
} else {
  ok('MONADGUARD_PRF_HEX', '32 bytes');
}

let account = null;
if (!process.env.PRIVATE_KEY) {
  warn('PRIVATE_KEY', 'unset — deploy and anchor unavailable');
} else {
  try {
    const pk = process.env.PRIVATE_KEY.startsWith('0x') ? process.env.PRIVATE_KEY : `0x${process.env.PRIVATE_KEY}`;
    account = privateKeyToAccount(pk);
    ok('attestor address', `${account.address} (derived from PRIVATE_KEY)`);
  } catch {
    fail('PRIVATE_KEY', 'malformed — expected 0x + 64 hex');
  }
}

const RPC_URL = process.env.RPC_URL
  ?? (process.env.ALCHEMY_KEY ? `https://monad-testnet.g.alchemy.com/v2/${process.env.ALCHEMY_KEY}` : 'https://testnet-rpc.monad.xyz');
process.env.ALCHEMY_KEY || process.env.RPC_URL
  ? ok('rpc transport', RPC_URL.replace(/\/v2\/.*$/, '/v2/***'))
  : warn('rpc transport', 'no ALCHEMY_KEY — falling back to the public endpoint, which rate-limits during demos');

// ── 4. Chain ──────────────────────────────────────────────────────────────
const chain = defineChain({
  id: CHAIN_ID,
  name: CHAIN_ID === 143 ? 'Monad' : 'Monad Testnet',
  nativeCurrency: { name: 'MON', symbol: 'MON', decimals: 18 },
  rpcUrls: { default: { http: [RPC_URL] } },
});
const client = createPublicClient({ chain, transport: http(RPC_URL, { timeout: 8000, retryCount: 0 }) });

let chainLive = false;
try {
  const [id, block] = await Promise.all([client.getChainId(), client.getBlockNumber()]);
  if (id !== CHAIN_ID) fail('rpc', `endpoint reports chain ${id}, CHAIN_ID says ${CHAIN_ID}`);
  else { ok('rpc', `chain ${id}, head block ${block}`); chainLive = true; }
} catch (e) {
  fail('rpc', (e.shortMessage ?? e.message).split('\n')[0]);
}

// ── 5. P256VERIFY, called directly ────────────────────────────────────────
// Deliberately not through the contract: this works before deploying, and it
// separates "the precompile is missing" from "my contract is wrong".
//
// The signature is generated here rather than hardcoded, and that matters: a
// call to an address with no code SUCCEEDS and returns empty, which is also
// RIP-7212's failure encoding. A canned vector therefore cannot tell "no
// precompile" from "bad input". A signature we just made is known-good, so
// anything other than 1 means the precompile is absent or broken.
if (chainLive) {
  const { deriveAttestorKey } = await import('./attestor.mjs');
  const { signDigest, precompileInput } = await import('../server/receipt.js');
  const probe = deriveAttestorKey(new Uint8Array(32).fill(3));
  const digest = '0x' + 'a5'.repeat(32);
  const sig = signDigest(digest, probe.privateKey);
  try {
    const res = await client.call({
      to: '0x0000000000000000000000000000000000000100',
      data: precompileInput(digest, sig, probe),
    });
    const out = res.data ?? '0x';
    if (out !== '0x' && BigInt(out) === 1n) ok('P256VERIFY (0x100)', 'live, verified a freshly signed vector');
    else fail('P256VERIFY (0x100)', `returned ${out === '0x' ? 'empty' : out} for a known-good signature — precompile absent or broken on chain ${CHAIN_ID}. The design does not work without it`);
  } catch (e) {
    fail('P256VERIFY (0x100)', (e.shortMessage ?? e.message).split('\n')[0]);
  }
}

// ── 6. Wallet ─────────────────────────────────────────────────────────────
if (chainLive && account) {
  try {
    const bal = await client.getBalance({ address: account.address });
    const mon = Number(bal) / 1e18;
    if (bal === 0n) fail('balance', '0 MON — fund from the testnet faucet before deploying');
    else if (mon < 0.05) warn('balance', `${mon.toFixed(4)} MON — thin for deploy + batches`);
    else ok('balance', `${mon.toFixed(4)} MON`);
  } catch (e) {
    warn('balance', (e.shortMessage ?? e.message).split('\n')[0]);
  }
}

// ── 7. Deployment ─────────────────────────────────────────────────────────
const depPath = `${root}/deployment.json`;
const dep = existsSync(depPath) ? JSON.parse(readFileSync(depPath, 'utf8')) : {};
const REGISTRY = process.env.REGISTRY_ADDRESS ?? dep.address ?? null;

if (!REGISTRY) {
  warn('registry', 'not deployed yet — run: npm run deploy');
} else if (chainLive) {
  try {
    const code = await client.getCode({ address: REGISTRY });
    if (!code || code === '0x') fail('registry', `no contract code at ${REGISTRY} on chain ${CHAIN_ID}`);
    else {
      ok('registry', `${REGISTRY} (${(code.length - 2) / 2} bytes)`);
      if (artifact && account) {
        const registered = await client.readContract({
          address: REGISTRY, abi: artifact.abi, functionName: 'isRegistered', args: [account.address],
        });
        registered
          ? ok('attestor registered', account.address)
          : warn('attestor registered', 'not yet — npm run e2e registers it on first run');
        const total = await client.readContract({ address: REGISTRY, abi: artifact.abi, functionName: 'totalAnchors' });
        ok('total anchors', String(total));
      }
    }
  } catch (e) {
    warn('registry', (e.shortMessage ?? e.message).split('\n')[0]);
  }
}

// ── 8. Local state ────────────────────────────────────────────────────────
try {
  const dbDir = (process.env.MONADGUARD_DB ?? `${root}/data/monadguard.db`).replace(/\/[^/]+$/, '');
  mkdirSync(dbDir, { recursive: true });
  const probe = `${dbDir}/.doctor-probe`;
  writeFileSync(probe, 'x'); unlinkSync(probe);
  const db = await import('../server/db.js');
  const s = db.stats();
  ok('sqlite', `writable — ${s.scans ?? 0} scans, ${s.anchored ?? 0} anchored, ${s.awaiting ?? 0} awaiting`);
} catch (e) {
  fail('sqlite', e.message.split('\n')[0]);
}

// ── 9. Indexer wiring ─────────────────────────────────────────────────────
const cfgPath = `${root}/indexer/config.yaml`;
if (existsSync(cfgPath)) {
  const cfg = readFileSync(cfgPath, 'utf8');
  if (cfg.includes('0x0000000000000000000000000000000000000000')) {
    warn('indexer/config.yaml', 'placeholder address — paste deployment.json address + deployBlock before envio codegen');
  } else if (REGISTRY && !cfg.toLowerCase().includes(REGISTRY.toLowerCase())) {
    warn('indexer/config.yaml', 'address does not match deployment.json — the indexer will watch the wrong contract');
  } else {
    ok('indexer/config.yaml', 'wired to the deployed address');
  }
}

// ── 10. Envio token ───────────────────────────────────────────────────────
const idxEnv = `${root}/indexer/.env`;
const tokenLine = existsSync(idxEnv) && readFileSync(idxEnv, 'utf8').split('\n').find((l) => /^\s*ENVIO_API_TOKEN\s*=\s*\S+/.test(l));
tokenLine || process.env.ENVIO_API_TOKEN
  ? ok('ENVIO_API_TOKEN', 'set — HyperSync available')
  : warn('ENVIO_API_TOKEN', 'missing in indexer/.env — HyperSync refuses, indexer falls back or stalls');

// ── 11. Public surface (read-only; skip with DOCTOR_OFFLINE=1) ────────────
if (!process.env.DOCTOR_OFFLINE) {
  const { publicChecks } = await import('./public-checks.mjs');
  for (const r of await publicChecks()) add(r.state, r.name, r.detail);
}

// ── Report ────────────────────────────────────────────────────────────────
const pad = Math.max(...rows.map((r) => r.name.length));
console.log('');
for (const r of rows) {
  const mark = r.state === 'OK' ? ' ok ' : r.state === 'WARN' ? 'warn' : 'FAIL';
  console.log(`  ${mark}  ${r.name.padEnd(pad)}  ${r.detail}`);
}
const warns = rows.filter((r) => r.state === 'WARN').length;
console.log(`\n  ${rows.length - failed - warns} ok, ${warns} warn, ${failed} fail\n`);
process.exit(failed ? 1 : 0);
