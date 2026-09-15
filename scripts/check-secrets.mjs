#!/usr/bin/env node
/**
 * Secret hygiene. Runs before `npm run dev` / `npm run deploy`, and as a
 * pre-commit hook once you run `node scripts/check-secrets.mjs --install-hook`.
 *
 * The repo is a hackathon deliverable — it goes public, and the judges clone it.
 * A leaked RPC key is somebody else burning your quota during the demo; a leaked
 * PRIVATE_KEY is the attestor identity the whole registry hangs on. This check
 * costs 200ms and removes the class of mistake entirely.
 *
 * Checks:
 *   1. .env exists and is NOT tracked by git
 *   2. .gitignore actually covers .env
 *   3. no tracked file contains something shaped like a key
 *   4. deployment.json carries no private material
 */
import { execSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, chmodSync, mkdirSync } from 'node:fs';

const INSTALL_HOOK = process.argv.includes('--install-hook');
const root = new URL('..', import.meta.url).pathname;

const SOFT_PATTERNS = [
  { name: 'bare 0x + 64 hex (hash or key — eyeball it)', re: /\b0x[0-9a-fA-F]{64}\b/ },
];

const PATTERNS = [
  { name: 'Alchemy-style RPC url with key', re: /g\.alchemy\.com\/v2\/[A-Za-z0-9_-]{20,}/ },
  { name: 'Tenderly gateway url with key', re: /gateway\.tenderly\.co\/[A-Za-z0-9_-]{20,}/ },
  { name: 'QuickNode url with key', re: /[a-z0-9-]+\.quiknode\.pro\/[a-f0-9]{20,}/ },
  { name: 'assigned PRIVATE_KEY', re: /PRIVATE_KEY\s*[=:]\s*['"]?0x?[0-9a-fA-F]{20,}/ },
  { name: 'assigned ALCHEMY_KEY', re: /ALCHEMY_KEY\s*[=:]\s*['"]?[A-Za-z0-9_-]{20,}/ },
  { name: 'PRF seed', re: /MONADGUARD_PRF_HEX\s*[=:]\s*['"]?[0-9a-fA-F]{64}/ },
  { name: 'assigned ENVIO_API_TOKEN', re: /ENVIO_API_TOKEN\s*[=:]\s*['"]?[A-Za-z0-9_-]{16,}/ },
];

// Test vectors and docs legitimately contain key-shaped strings.
const ALLOWLIST = [
  /^test\//, /^scripts\/attestor\.test\.mjs$/, /^scripts\/check-secrets\.mjs$/,
  /^\.env\.example$/, /^package-lock\.json$/, /^build\//,
];

const git = (cmd) => execSync(`git ${cmd}`, { cwd: root, encoding: 'utf8' }).trim();
const problems = [];
const warn = [];

let tracked = [];
try {
  tracked = git('ls-files').split('\n').filter(Boolean);
} catch {
  console.log('[secrets] not a git repo yet — skipping tracked-file scan');
}

// 1 + 2: .env handling
const trackedEnv = tracked.filter((f) => f === '.env' || f.endsWith('/.env'));
for (const f of trackedEnv) problems.push(`${f} is TRACKED BY GIT. \`git rm --cached ${f}\` and rotate every key in it.`);
if (!existsSync(`${root}/.gitignore`) || !/^\.env\s*$/m.test(readFileSync(`${root}/.gitignore`, 'utf8'))) {
  problems.push('.gitignore does not cover `.env`');
}
if (!existsSync(`${root}/.env`) && !process.env.PRIVATE_KEY) {
  warn.push('no .env and no PRIVATE_KEY in the environment — deploy and anchor will fail');
}

// 3: scan tracked content
for (const file of tracked) {
  if (ALLOWLIST.some((re) => re.test(file))) continue;
  let content;
  try { content = readFileSync(`${root}/${file}`, 'utf8'); } catch { continue; }
  for (const { name, re } of PATTERNS) {
    const hit = content.match(re);
    if (hit) problems.push(`${file}: looks like a ${name} — ${hit[0].slice(0, 24)}…`);
  }
  for (const { name, re } of SOFT_PATTERNS) {
    const hit = content.match(re);
    if (hit) warn.push(`${file}: ${name} — ${hit[0].slice(0, 24)}…`);
  }
}

// 4: deployment.json
if (existsSync(`${root}/deployment.json`)) {
  const dep = JSON.parse(readFileSync(`${root}/deployment.json`, 'utf8'));
  for (const k of Object.keys(dep)) {
    if (/priv|secret|key/i.test(k) && k !== 'attestorKey') problems.push(`deployment.json contains suspicious field "${k}"`);
  }
}

if (INSTALL_HOOK) {
  mkdirSync(`${root}/.git/hooks`, { recursive: true });
  writeFileSync(`${root}/.git/hooks/pre-commit`, '#!/bin/sh\nnode scripts/check-secrets.mjs || exit 1\n');
  chmodSync(`${root}/.git/hooks/pre-commit`, 0o755);
  console.log('[secrets] pre-commit hook installed');
}

for (const w of warn) console.warn(`[secrets] warn: ${w}`);
if (problems.length) {
  console.error('\n[secrets] BLOCKED:');
  for (const p of problems) console.error(`  - ${p}`);
  console.error('\nNothing was committed or started. Fix these, then rotate anything that was exposed.\n');
  process.exit(1);
}
console.log(`[secrets] ok — ${tracked.length} tracked files clean`);
