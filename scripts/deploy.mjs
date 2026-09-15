// Deploy ScanRegistry to Monad. No Foundry needed — viem is already in the stack.
//   node scripts/deploy.mjs
// Env: PRIVATE_KEY, RPC_URL, CHAIN_ID (10143 testnet | 143 mainnet)
import '../server/env.js';
import { createWalletClient, createPublicClient, http, defineChain } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { readFileSync, writeFileSync } from 'node:fs';

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

const bal = await pub.getBalance({ address: account.address });
console.log(`deployer ${account.address} | balance ${bal} wei | chain ${CHAIN_ID}`);
if (bal === 0n) throw new Error('deployer has no MON — fund it first');

const hash = await wallet.deployContract({ abi: artifact.abi, bytecode: artifact.bytecode, args: [] });
console.log('tx', hash);
const rcpt = await pub.waitForTransactionReceipt({ hash });
console.log('ScanRegistry deployed at', rcpt.contractAddress, 'block', rcpt.blockNumber);

writeFileSync(new URL('../deployment.json', import.meta.url), JSON.stringify({
  chainId: CHAIN_ID, address: rcpt.contractAddress,
  deployBlock: Number(rcpt.blockNumber), txHash: hash, deployer: account.address,
}, null, 2));
console.log('-> deployment.json written (use deployBlock as Envio start_block)');
