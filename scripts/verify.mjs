#!/usr/bin/env node
/**
 * npm run verify — publish ScanRegistry's source to Sourcify, which MonadVision reads.
 *
 * Rebuilds the exact standard-JSON input compile.cjs used (same file name, same
 * settings), checks locally that it reproduces build/ScanRegistry.json byte for
 * byte, then submits it. Sourcify recompiles and compares against the deployed
 * bytecode, including the metadata hash, so an exact input gives a full match.
 *
 * Env: SOURCIFY_URL (default: BlockVision's Sourcify for Monad), CHAIN_ID / REGISTRY_ADDRESS
 * override deployment.json.
 */
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const solc = require('solc');

const root = new URL('..', import.meta.url);
const dep = JSON.parse(readFileSync(new URL('deployment.json', root), 'utf8'));
const CHAIN_ID = String(process.env.CHAIN_ID ?? dep.chainId);
const ADDRESS = process.env.REGISTRY_ADDRESS ?? dep.address;
const SOURCIFY = (process.env.SOURCIFY_URL ?? 'https://sourcify-api-monad.blockvision.org').replace(/\/$/, '');

const stdJsonInput = {
  language: 'Solidity',
  sources: { 'ScanRegistry.sol': { content: readFileSync(new URL('contracts/ScanRegistry.sol', root), 'utf8') } },
  settings: {
    optimizer: { enabled: true, runs: 200 },
    evmVersion: 'shanghai',
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'metadata'] } },
  },
};

// 1. Local reproducibility check: never submit something that cannot match.
const out = JSON.parse(solc.compile(JSON.stringify(stdJsonInput)));
const errs = (out.errors ?? []).filter((e) => e.severity === 'error');
if (errs.length) { console.error(errs.map((e) => e.formattedMessage).join('\n')); process.exit(1); }
const built = '0x' + out.contracts['ScanRegistry.sol'].ScanRegistry.evm.bytecode.object;
const artifact = JSON.parse(readFileSync(new URL('build/ScanRegistry.json', root), 'utf8'));
if (built !== artifact.bytecode) {
  console.error('local compile does not reproduce build/ScanRegistry.json — source or settings drifted since deploy. Not submitting.');
  process.exit(1);
}
const compilerVersion = solc.version().replace(/\.Emscripten.*$/, '');
console.log(`reproduced deployed artifact with solc ${compilerVersion}`);
console.log(`submitting ${ADDRESS} on chain ${CHAIN_ID} to ${SOURCIFY}`);

const j = async (r) => { const t = await r.text(); try { return JSON.parse(t); } catch { return { raw: t.slice(0, 300) }; } };

// 2. Sourcify API v2 (async job), falling back to the legacy endpoint.
async function v2() {
  const r = await fetch(`${SOURCIFY}/v2/verify/${CHAIN_ID}/${ADDRESS}`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      stdJsonInput, compilerVersion,
      contractIdentifier: 'ScanRegistry.sol:ScanRegistry',
      ...(dep.txHash && CHAIN_ID === String(dep.chainId) ? { creationTransactionHash: dep.txHash } : {}),
    }),
  });
  const body = await j(r);
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`v2 ${r.status}: ${JSON.stringify(body)}`);
  for (let i = 0; i < 30; i++) {
    await new Promise((s) => setTimeout(s, 3000));
    const s = await j(await fetch(`${SOURCIFY}/v2/verify/${body.verificationId}`));
    if (s.isJobCompleted) {
      if (s.error) throw new Error(`${s.error.customCode}: ${s.error.message}`);
      return s.contract?.match ?? s.contract?.runtimeMatch ?? 'match';
    }
  }
  throw new Error('v2 job did not finish in 90s');
}

async function legacy() {
  const r = await fetch(`${SOURCIFY}/verify/solc-json`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      address: ADDRESS, chain: CHAIN_ID, compilerVersion, contractName: 'ScanRegistry',
      files: { 'input.json': JSON.stringify(stdJsonInput) },
    }),
  });
  const body = await j(r);
  if (!r.ok) throw new Error(`legacy ${r.status}: ${JSON.stringify(body)}`);
  return body.result?.[0]?.status ?? JSON.stringify(body);
}

try {
  const res = (await v2()) ?? (await legacy());
  console.log(`verified: ${res}`);
  console.log(`check: ${CHAIN_ID === '143' ? 'https://monadvision.com' : 'https://testnet.monadvision.com'}/address/${ADDRESS}`);
} catch (e) {
  if (/already/i.test(e.message)) console.log('already verified');
  else { console.error(e.message); process.exit(1); }
}
