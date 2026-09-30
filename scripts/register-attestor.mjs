#!/usr/bin/env node
/**
 * npm run register — bind this node's P-256 key to its EVM address on the
 * configured chain, and nothing else.
 *
 * e2e does this too, but it goes on to anchor a synthetic fixture. On mainnet
 * the registry should hold real tools only, so registration needs a door of its
 * own. Idempotent: already registered is a no-op, not an error.
 *
 * Env: CHAIN_ID, PRIVATE_KEY, MONADGUARD_PRF_HEX, BASE_URL (for metaURI).
 */
import '../server/env.js';
import * as chain from '../server/chain.js';
import { loadAttestor, publicAttestor } from '../server/keys.js';

const key = loadAttestor({ allowDevKey: process.env.NODE_ENV !== 'production' });
if (!key) throw new Error('no attestor key — set MONADGUARD_PRF_HEX');

const { account } = chain.wallet();
const pub = publicAttestor(key);

await chain.assertChain();
console.log(`chain    ${chain.CHAIN_ID}`);
console.log(`registry ${chain.REGISTRY}`);
console.log(`attestor ${account.address}`);
console.log(`P-256    x ${pub.x}\n         y ${pub.y}`);

const balance = await chain.publicClient.getBalance({ address: account.address });
console.log(`balance  ${balance} wei`);
if (balance === 0n) throw new Error('this account has no MON on this chain');

// The precompile is what makes the registration meaningful: the contract
// verifies proof of possession with it. If it misbehaves here, learn it now.
if (!(await chain.precompileAlive(key))) {
  throw new Error('P256VERIFY did not verify a known-good signature on this chain — stop and investigate');
}
console.log('P256VERIFY verifies a known-good signature: true');

if (await chain.isRegistered(account.address)) {
  const [x, y] = await chain.read('attestorKey', [account.address]);
  const same = x.toLowerCase() === pub.x.toLowerCase() && y.toLowerCase() === pub.y.toLowerCase();
  console.log(`\nalready registered — stored key ${same ? 'matches this one' : 'is DIFFERENT (another key is registered to this address)'}`);
  process.exit(same ? 0 : 1);
}

const metaURI = process.env.META_URI ?? `${(process.env.BASE_URL ?? 'https://api.monadguard.com').replace(/\/$/, '')}/#attestor/${account.address}`;
console.log(`\nregistering with metaURI ${metaURI}`);
const reg = await chain.registerAttestor(key, metaURI);
const rcpt = await chain.publicClient.getTransactionReceipt({ hash: reg.hash });
console.log(`tx ${reg.hash}`);
console.log(`block ${reg.block} status ${reg.status} gas used ${rcpt.gasUsed}`);
