import { deriveAttestorKey, signReceipt, verifyReceipt, precompileInput, SALT } from './attestor.mjs';
const prf = new Uint8Array(32).fill(7);               // stand-in for Mera PRF output
const k1 = deriveAttestorKey(prf);
const k2 = deriveAttestorKey(new Uint8Array(32).fill(7)); // "second device", same passkey
console.log('deterministic across devices:', k1.publicKeyUncompressed === k2.publicKeyUncompressed);
const k3 = deriveAttestorKey(new Uint8Array(32).fill(8)); // different passkey
console.log('different passkey -> different identity:', k1.x !== k3.x);
const payload = { toolId:'0xaa', contentHash:'0xbb', verdict:3, score:91, attestor:k1.publicKeyUncompressed, ts:1788000000 };
const sig = signReceipt(payload, k1.privateKey);
console.log('verify ok:', verifyReceipt(payload, sig, k1));
console.log('tamper rejected:', !verifyReceipt({...payload, verdict:1}, sig, k1));
const inp = precompileInput(sig, k1);
console.log('precompile input bytes:', (inp.length-2)/2, '(must be 160)');
console.log('salts distinct:', Buffer.compare(Buffer.from(SALT.ATTESTOR), Buffer.from(SALT.VAULT)) !== 0);
