#!/usr/bin/env node
// npm run check:public — safe to run anytime, from anywhere. Read-only.
import { publicChecks } from './public-checks.mjs';
const rows = await publicChecks();
const pad = Math.max(...rows.map((r) => r.name.length));
for (const r of rows) console.log(`  ${r.state === 'OK' ? ' ok ' : r.state === 'WARN' ? 'warn' : 'FAIL'}  ${r.name.padEnd(pad)}  ${r.detail}`);
process.exit(rows.some((r) => r.state === 'FAIL') ? 1 : 0);
