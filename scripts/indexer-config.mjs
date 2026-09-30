#!/usr/bin/env node
/**
 * npm run indexer:config — point indexer/config.yaml at the active deployment.
 *
 * Three values in that file have to agree with deployment.json: the chain id,
 * the contract address and the start block. Hand-editing them is how an indexer
 * ends up silently indexing nothing — a wrong start_block just yields an empty
 * registry, with no error anywhere.
 *
 * Prints the result and, unless --write is passed, changes nothing.
 */
import { readFileSync, writeFileSync } from 'node:fs';

const dep = JSON.parse(readFileSync(new URL('../deployment.json', import.meta.url), 'utf8'));
const path = new URL('../indexer/config.yaml', import.meta.url);
const before = readFileSync(path, 'utf8');

if (!dep.chainId || !dep.address || !Number.isInteger(dep.deployBlock)) {
  throw new Error(`deployment.json is incomplete: ${JSON.stringify(dep)}`);
}

const after = before
  .replace(/^(\s*- id:\s*)\d+/m, `$1${dep.chainId}`)
  .replace(/^(\s*start_block:\s*)\d+/m, `$1${dep.deployBlock}`)
  .replace(/^(\s*- ")0x[0-9a-fA-F]{40}(")/m, `$1${dep.address}$2`);

const chains = after.slice(after.indexOf('chains:'));
console.log(`deployment.json -> chain ${dep.chainId}, ${dep.address}, block ${dep.deployBlock}\n`);
console.log(chains.split('\n').slice(0, 8).join('\n'));

if (!after.includes(dep.address)) throw new Error('address line not found in config.yaml — edit it by hand and fix this script');
if (before === after) { console.log('\nalready up to date'); process.exit(0); }
if (!process.argv.includes('--write')) { console.log('\ndry run. apply with: npm run indexer:config -- --write'); process.exit(0); }

writeFileSync(path, after);
console.log('\nconfig.yaml written. A chain change needs a full reindex:');
console.log('  pm2 stop monadguard-indexer && cd indexer && TUI_OFF=true npx envio dev -r');
