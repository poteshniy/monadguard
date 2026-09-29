#!/usr/bin/env node
/**
 * npm run gas — what the mainnet move will actually cost, before any of it is spent.
 *
 *   MAINNET_RPC_URL=… node scripts/gas-estimate.mjs [--anchors 25]
 *
 * Read-only. It sends nothing and signs nothing.
 *
 * Two different kinds of number come out of this, and the report says which is
 * which, because trusting a guess with real money is how people lose it:
 *
 *   measured  gas actually burned by our own transactions on testnet. Gas used
 *             is a property of the EVM work, not of the network, so the same
 *             call costs the same units on mainnet.
 *   estimated gas the mainnet node itself quotes for the deploy (exact), or a
 *             stated constant where we have no sample yet.
 *
 * The price is the part that moves. Everything is quoted at the current price
 * and again at 3x, because a deploy that lands during a busy block should not
 * be a surprise.
 */
import '../server/env.js';
import { createPublicClient, http, defineChain, formatEther } from 'viem';
import { readFileSync } from 'node:fs';
import * as db from '../server/db.js';

const ANCHORS = Number(process.argv[process.argv.indexOf('--anchors') + 1]) || 25;
const MAINNET_RPC = process.env.MAINNET_RPC_URL
  ?? (process.env.ALCHEMY_KEY ? `https://monad-mainnet.g.alchemy.com/v2/${process.env.ALCHEMY_KEY}` : 'https://rpc.monad.xyz');
const TESTNET_RPC = process.env.RPC_URL
  ?? (process.env.ALCHEMY_KEY ? `https://monad-testnet.g.alchemy.com/v2/${process.env.ALCHEMY_KEY}` : 'https://testnet-rpc.monad.xyz');

const chain = (id, url) => defineChain({
  id, name: id === 143 ? 'Monad' : 'Monad Testnet',
  nativeCurrency: { name: 'MON', symbol: 'MON', decimals: 18 },
  rpcUrls: { default: { http: [url] } },
});
const main = createPublicClient({ chain: chain(143, MAINNET_RPC), transport: http(MAINNET_RPC) });
const test = createPublicClient({ chain: chain(10143, TESTNET_RPC), transport: http(TESTNET_RPC) });

const id = await main.getChainId();
if (id !== 143) throw new Error(`MAINNET_RPC_URL points at chain ${id}, not 143`);

const artifact = JSON.parse(readFileSync(new URL('../build/ScanRegistry.json', import.meta.url)));

// The deploy is the one call a node can quote exactly without the contract
// existing: it is just calldata.
// Some nodes simulate the balance check even for an estimate, which fails on an
// account that has not been funded yet — which is exactly when this is run.
let deployGas, deployNote = 'estimated by the mainnet node';
try {
  deployGas = await main.estimateGas({ account: process.env.DEPLOYER ?? '0x79732eE50342D093402F7D5731d689D11E61c423', data: artifact.bytecode });
} catch {
  try {
    deployGas = await main.estimateGas({ data: artifact.bytecode });
  } catch (e) {
    deployGas = 3_000_000n;
    deployNote = `ASSUMED — the node would not estimate (${String(e.shortMessage ?? e.message).slice(0, 40)})`;
  }
}

/** Average gas actually used by our own anchors on testnet. */
async function measured(limit = 5) {
  const rows = db.db.prepare(
    "SELECT anchor_tx FROM scans WHERE anchor_state = 'confirmed' AND anchor_tx IS NOT NULL ORDER BY created_at DESC LIMIT ?"
  ).all(limit);
  const used = [];
  for (const r of rows) {
    try { used.push(Number((await test.getTransactionReceipt({ hash: r.anchor_tx })).gasUsed)); } catch {}
  }
  return used.length ? Math.round(used.reduce((a, b) => a + b) / used.length) : null;
}

const anchorGas = await measured();
// No sample: a registerAttestor carries a P256VERIFY call and two storage
// writes. Stated, not measured — it is marked as such in the output.
const REGISTER_GAS_ASSUMED = 150_000;

const price = await main.getGasPrice();
const rows = [
  ['deploy ScanRegistry', deployGas, 1, deployNote],
  ['registerAttestor', BigInt(REGISTER_GAS_ASSUMED), 1, 'ASSUMED — no sample to measure'],
  ['anchorScan', BigInt(anchorGas ?? 200_000), ANCHORS, anchorGas ? `measured on testnet (avg of our own anchors)` : 'ASSUMED — no confirmed anchor in this database'],
];

const cost = (gas, n, p) => gas * BigInt(n) * p;
const total = (p) => rows.reduce((sum, [, gas, n]) => sum + cost(gas, n, p), 0n);

console.log(`\nmainnet RPC  ${MAINNET_RPC.replace(/\/v2\/.*$/, '/v2/***')}`);
console.log(`gas price    ${Number(price) / 1e9} gwei (now)\n`);
const pad = Math.max(...rows.map((r) => r[0].length));
for (const [name, gas, n, note] of rows) {
  console.log(`  ${name.padEnd(pad)}  ${String(gas).padStart(9)} gas × ${String(n).padStart(2)}  = ${formatEther(cost(gas, n, price)).slice(0, 10).padStart(11)} MON   ${note}`);
}
console.log(`\n  ${'TOTAL at the current price'.padEnd(pad + 24)}${formatEther(total(price)).slice(0, 10).padStart(11)} MON`);
console.log(`  ${'TOTAL at 3x the price'.padEnd(pad + 24)}${formatEther(total(price * 3n)).slice(0, 10).padStart(11)} MON`);
console.log(`\nFund the deployer with the 3x figure and a little over; the passkey`);
console.log(`attestor needs its own gas for one registerAttestor — there is no`);
console.log(`faucet on mainnet, deliberately.\n`);
