// Deploy ScanRegistry to Monad. No Foundry needed — viem is already in the stack.
//   node scripts/deploy.mjs
// Env: PRIVATE_KEY, RPC_URL, CHAIN_ID (10143 testnet | 143 mainnet)
import '../server/env.js';
import { createWalletClient, createPublicClient, http, defineChain } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';

const CHAIN_ID = Number(process.env.CHAIN_ID ?? 10143);
const RPC_URL = process.env.RPC_URL ?? (CHAIN_ID === 143
  ? 'https://rpc.monad.xyz'
  : 'https://testnet-rpc.monad.xyz');
const PK = process.env.PRIVATE_KEY;
if (!PK) throw new Error('set PRIVATE_KEY');

const monad = defineChain({
  id: CHAIN_ID,
  name: CHAIN_ID === 143 ? 'Monad' : 'Monad Testnet',
  nativeCurrency: { name: 'MON', symbol: 'MON', decimals: 18 },
  rpcUrls: { default: { http: [RPC_URL] } },
});

const artifact = JSON.parse(readFileSync(new URL('../build/ScanRegistry.json', import.meta.url)));
const account = privateKeyToAccount(PK.startsWith('0x') ? PK : `0x${PK}`);
const wallet = createWalletClient({ account, chain: monad, transport: http(RPC_URL) });
const pub = createPublicClient({ chain: monad, transport: http(RPC_URL) });

// Mainnet costs real money and cannot be undone. Ask the RPC which chain it is
// on rather than trusting that CHAIN_ID and RPC_URL were changed together.
const actual = await pub.getChainId();
if (actual !== CHAIN_ID) throw new Error(`chain mismatch: CHAIN_ID=${CHAIN_ID} but the RPC is ${actual} — check RPC_URL`);

const bal = await pub.getBalance({ address: account.address });
console.log(`deployer ${account.address} | balance ${bal} wei | chain ${CHAIN_ID}`);
if (bal === 0n) throw new Error('deployer has no MON — fund it first');

if (CHAIN_ID === 143 && !process.argv.includes('--yes-mainnet')) {
  throw new Error('this deploys to Monad MAINNET with real MON. Re-run with --yes-mainnet if that is what you mean.');
}

const hash = await wallet.deployContract({ abi: artifact.abi, bytecode: artifact.bytecode, args: [] });
console.log('tx', hash);
const rcpt = await pub.waitForTransactionReceipt({ hash });
console.log('ScanRegistry deployed at', rcpt.contractAddress, 'block', rcpt.blockNumber);

const record = {
  chainId: CHAIN_ID, address: rcpt.contractAddress,
  deployBlock: Number(rcpt.blockNumber), txHash: hash, deployer: account.address,
};

// deployment.json is the ACTIVE network. Deploying to a second one used to
// overwrite it, and with it the only record of where the first registry lives —
// the anchors there stay valid forever and still need to be findable.
mkdirSync(new URL('../deployments/', import.meta.url), { recursive: true });
writeFileSync(new URL(`../deployments/${CHAIN_ID}.json`, import.meta.url), JSON.stringify(record, null, 2));
writeFileSync(new URL('../deployment.json', import.meta.url), JSON.stringify(record, null, 2));
console.log(`-> deployment.json + deployments/${CHAIN_ID}.json written (use deployBlock as Envio start_block)`);
