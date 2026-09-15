/**
 * Loads .env into process.env. Import this FIRST in every entrypoint.
 * Real environment variables win over the file, so PM2 env blocks and
 * `PRIVATE_KEY=0x… npm run deploy` still override it.
 */
import { existsSync, readFileSync } from 'node:fs';

const path = process.env.ENV_FILE ?? new URL('../.env', import.meta.url).pathname;

if (existsSync(path)) {
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    if (/^\s*(#|$)/.test(line)) continue;
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!m) continue;
    const [, key, raw] = m;
    if (process.env[key] !== undefined) continue;
    process.env[key] = raw.replace(/^(['"])(.*)\1$/, '$2');
  }
}

export const ENV_PATH = path;
export const ENV_LOADED = existsSync(path);
