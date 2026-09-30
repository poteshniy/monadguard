#!/usr/bin/env node
/**
 * npm run agent:register            dry run: print the card and what would be sent
 * npm run agent:register -- --send  mint the ERC-8004 identity
 *
 * Registers MonadGuard in the ERC-8004 Identity Registry on the configured
 * chain. `register(agentURI)` mints an ERC-721 whose token URI is our
 * registration document; the agent id comes back in the Registered event.
 *
 * Order matters: the URI has to resolve before it is registered, because that
 * document is the only thing a reader gets. So this refuses to send until the
 * live URI answers with a card that matches the one this node would serve.
 *
 * Afterwards: put AGENT_ID=<id> in .env and restart, so the card names its own
 * registration.
 */
import '../server/env.js';
import { parseEventLogs } from 'viem';
import * as chain from '../server/chain.js';
import { agentCard, agentURI } from '../server/agent-card.js';

const SEND = process.argv.includes('--send');
const REGISTRY_8004 = process.env.AGENT_REGISTRY ?? '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432';

const ABI = [
  { type: 'function', name: 'register', stateMutability: 'nonpayable', inputs: [{ name: 'agentURI', type: 'string' }], outputs: [{ name: 'agentId', type: 'uint256' }] },
  { type: 'event', name: 'Registered', inputs: [
    { name: 'agentId', type: 'uint256', indexed: true },
    { name: 'agentURI', type: 'string', indexed: false },
    { name: 'owner', type: 'address', indexed: true },
  ] },
];

const card = agentCard();
console.log(`chain     ${chain.CHAIN_ID}`);
console.log(`registry  ${REGISTRY_8004}`);
console.log(`agentURI  ${agentURI}`);
console.log(`\n${JSON.stringify(card, null, 1)}\n`);

if (card.registrations.length) {
  console.log(`AGENT_ID is already set to ${card.registrations[0].agentId}. Registering again would mint a second identity.`);
  if (SEND) process.exit(1);
}

await chain.assertChain();
const code = await chain.publicClient.getCode({ address: REGISTRY_8004 });
if (!code || code === '0x') throw new Error(`no ERC-8004 registry at ${REGISTRY_8004} on chain ${chain.CHAIN_ID}`);

// The document is the registration. If the URI does not resolve, or resolves to
// something other than what this node serves, the entry would point at nothing
// a reader can trust.
let live;
try {
  const r = await fetch(agentURI, { signal: AbortSignal.timeout(8000) });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  live = await r.json();
} catch (e) {
  console.error(`\n${agentURI} does not resolve (${e.message}).`);
  console.error('Deploy the card first — it is what the registration points at.');
  process.exit(1);
}
if (live.name !== card.name || JSON.stringify(live.services) !== JSON.stringify(card.services)) {
  console.error(`\nthe live document differs from what this checkout would serve — restart the API first`);
  process.exit(1);
}
console.log(`live document at ${agentURI} matches this checkout`);

const { account, client } = chain.wallet();
const balance = await chain.publicClient.getBalance({ address: account.address });
console.log(`owner     ${account.address}  balance ${balance} wei`);
if (balance === 0n) throw new Error('this account has no MON on this chain');

if (!SEND) { console.log('\ndry run. send it with: npm run agent:register -- --send'); process.exit(0); }

const hash = await client.writeContract({ address: REGISTRY_8004, abi: ABI, functionName: 'register', args: [agentURI] });
console.log(`tx ${hash}`);
const receipt = await chain.publicClient.waitForTransactionReceipt({ hash, timeout: 90_000 });
if (receipt.status !== 'success') throw new Error(`register reverted (${hash})`);

const [ev] = parseEventLogs({ abi: ABI, eventName: 'Registered', logs: receipt.logs });
const agentId = ev ? Number(ev.args.agentId) : null;
console.log(`block ${receipt.blockNumber} gas used ${receipt.gasUsed}`);
console.log(`\nagentId ${agentId ?? '(not in the logs — read it from the explorer)'}`);
console.log(`\nNow put this in .env and restart, so the card names its own registration:`);
console.log(`  AGENT_ID=${agentId ?? '<id>'}`);
console.log(`  pm2 restart monadguard-api --update-env`);
