/**
 * Digest parity: Solidity vs JavaScript.
 *
 * `anchorDigest` is computed independently on both sides. If abi.encodePacked
 * and viem's encodePacked disagree by a single byte, every anchor reverts with
 * BadSignature and the cause is invisible from the revert. This test runs the
 * actual compiled bytecode in a local EVM and compares.
 *
 * The local EVM has no P256VERIFY at 0x100, which also exercises the
 * "staticcall succeeds, returndata empty" path: verifySignature must return
 * false rather than revert.
 *
 *   node test/parity.test.mjs
 */
import { createEVM } from '@ethereumjs/evm';
import * as ejsUtil from '@ethereumjs/util';
const toAddress = ejsUtil.createAddressFromString ?? ((a) => ejsUtil.Address.fromString(a));
const ejsHexToBytes = ejsUtil.hexToBytes;
const ejsBytesToHex = ejsUtil.bytesToHex;
import { readFileSync } from 'node:fs';
import { encodeFunctionData, decodeFunctionResult } from 'viem';
import { anchorDigest, registrationDigest, signDigest, precompileInput } from '../server/receipt.js';
import { deriveAttestorKey } from '../scripts/attestor.mjs';

const artifact = JSON.parse(readFileSync(new URL('../build/ScanRegistry.json', import.meta.url)));
const CHAIN_ID = 1; // @ethereumjs/evm default common
const REGISTRY = '0x00000000000000000000000000000000000c0de1';
const ATTESTOR = '0x1111111111111111111111111111111111111111';

const evm = await createEVM();
const addr = toAddress(REGISTRY);
// Deploy by executing the creation code, then install the returned runtime code.
const created = await evm.runCall({
  data: ejsHexToBytes(artifact.bytecode),
  gasLimit: 10_000_000n,
});
if (created.execResult.exceptionError) throw new Error('deploy failed: ' + created.execResult.exceptionError.error);
await evm.stateManager.putCode(addr, created.execResult.returnValue);

async function call(functionName, args) {
  const res = await evm.runCall({
    to: addr,
    caller: toAddress(ATTESTOR),
    data: ejsHexToBytes(encodeFunctionData({ abi: artifact.abi, functionName, args })),
    gasLimit: 5_000_000n,
  });
  if (res.execResult.exceptionError) throw new Error(`${functionName}: ${res.execResult.exceptionError.error}`);
  return decodeFunctionResult({ abi: artifact.abi, functionName, data: ejsBytesToHex(res.execResult.returnValue) });
}

let failures = 0;
const check = (name, ok, extra = '') => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${extra ? '  ' + extra : ''}`);
  if (!ok) failures++;
};

// ── anchorDigest parity ───────────────────────────────────────
const params = {
  toolId: '0x' + 'aa'.repeat(32),
  contentHash: '0x' + 'bb'.repeat(32),
  verdict: 3,
  score: 91,
  receiptHash: '0x' + 'cc'.repeat(32),
};
const solAnchor = await call('anchorDigest', [ATTESTOR, params.toolId, params.contentHash, params.verdict, params.score, params.receiptHash]);
const jsAnchor = anchorDigest({ chainId: CHAIN_ID, registry: REGISTRY, attestor: ATTESTOR, ...params });
check('anchorDigest parity', solAnchor.toLowerCase() === jsAnchor.toLowerCase(), `\n     sol ${solAnchor}\n     js  ${jsAnchor}`);

// edge: verdict 0 / score 0 (uint8 and uint16 zero-byte packing)
const zeroParams = { ...params, verdict: 0, score: 0 };
const solZero = await call('anchorDigest', [ATTESTOR, zeroParams.toolId, zeroParams.contentHash, 0, 0, zeroParams.receiptHash]);
const jsZero = anchorDigest({ chainId: CHAIN_ID, registry: REGISTRY, attestor: ATTESTOR, ...zeroParams });
check('anchorDigest parity (zero verdict/score)', solZero.toLowerCase() === jsZero.toLowerCase());

// changing one field must change the digest — proves the binding is real
check('digest binds verdict', solAnchor.toLowerCase() !== solZero.toLowerCase());

// ── registrationDigest parity ─────────────────────────────────
const key = deriveAttestorKey(new Uint8Array(32).fill(7));
const solReg = await call('registrationDigest', [ATTESTOR, key.x, key.y]);
const jsReg = registrationDigest({ chainId: CHAIN_ID, registry: REGISTRY, attestor: ATTESTOR, x: key.x, y: key.y });
check('registrationDigest parity', solReg.toLowerCase() === jsReg.toLowerCase(), `\n     sol ${solReg}\n     js  ${jsReg}`);

// ── precompile input shape + graceful absence ─────────────────
const sig = signDigest(jsAnchor, key.privateKey);
const input = precompileInput(jsAnchor, sig, key);
check('precompile input is 160 bytes', (input.length - 2) / 2 === 160);

const verified = await call('verifySignature', [jsAnchor, sig.r, sig.s, key.x, key.y]);
check('verifySignature returns false (no precompile locally, no revert)', verified === false);

console.log(failures === 0 ? '\nPARITY OK' : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
