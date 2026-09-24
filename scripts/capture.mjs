#!/usr/bin/env node
/**
 * npm run capture -- <npm-package> [-- server args]
 * npm run capture -- --file scripts/capture/targets.json --out capture/
 *
 * Captures an MCP server's real tools/list so it can be scanned.
 *
 * THIS RUNS THIRD-PARTY CODE. Never on the host, never as a service:
 *   install phase  network on, `--ignore-scripts` (a postinstall hook is the
 *                  cheapest RCE there is), throwaway directory, non-root
 *   probe phase    `--network none`, no host mounts beyond that directory,
 *                  memory and pid caps, killed after a timeout
 * A public endpoint that did this would be an RCE next to PRIVATE_KEY. There
 * is none, and there will not be one.
 */
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile, readFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const run = promisify(execFile);
const IMAGE = process.env.CAPTURE_IMAGE ?? 'node:22-alpine';
const PROBE = new URL('capture/probe.mjs', import.meta.url).pathname;

export async function capture(pkg, { args = [], timeoutMs = 120000 } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'mg-capture-'));
  try {
    await run('docker', ['run', '--rm', '-v', `${dir}:/w`, '-w', '/w', '-u', '1000:1000',
      '-e', 'HOME=/tmp', '--memory', '1g', '--pids-limit', '512', IMAGE,
      'npm', 'install', '--no-audit', '--no-fund', '--ignore-scripts', '--silent', pkg,
    ], { timeout: timeoutMs, maxBuffer: 32 * 1024 * 1024 });

    await writeFile(join(dir, 'probe.mjs'), await readFile(PROBE, 'utf8'));

    const { stdout } = await run('docker', ['run', '--rm', '--network', 'none', '-v', `${dir}:/w`, '-w', '/w',
      '-u', '1000:1000', '-e', 'HOME=/tmp', '--memory', '512m', '--pids-limit', '256', IMAGE,
      'node', '/w/probe.mjs', pkg, ...args,
    ], { timeout: 60000, maxBuffer: 16 * 1024 * 1024 });

    const line = stdout.trim().split('\n').filter((l) => l.startsWith('{')).pop();
    return JSON.parse(line);
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

/** tools/list output -> the manifest shape the scanner and toolId expect. */
export const toManifest = (cap) => ({
  name: cap.server?.name ?? cap.package,
  version: cap.server?.version ?? cap.version,
  ...(cap.instructions ? { description: cap.instructions } : {}),
  tools: cap.tools ?? [],
  ...(cap.resources?.length ? { resources: cap.resources } : {}),
  ...(cap.prompts?.length ? { prompts: cap.prompts } : {}),
});

if (import.meta.url === `file://${process.argv[1]}`) {
  const argv = process.argv.slice(2);
  const flag = (n, d) => { const i = argv.indexOf(`--${n}`); return i === -1 ? d : argv[i + 1]; };
  const out = flag('out', 'capture');
  const file = flag('file');
  const flagValues = new Set(['out', 'file'].map((n) => flag(n)).filter(Boolean));
  const targets = file
    ? JSON.parse(await readFile(file, 'utf8'))
    : argv.filter((a) => !a.startsWith('--') && !flagValues.has(a)).map((name) => ({ name }));
  if (!targets.length) { console.error('usage: npm run capture -- <package> | --file targets.json'); process.exit(1); }

  await mkdir(out, { recursive: true });
  const index = [];
  for (const t of targets) {
    const label = `${t.name}${t.args?.length ? ' ' + t.args.join(' ') : ''}`;
    process.stdout.write(`${label.padEnd(48)} `);
    try {
      const cap = await capture(t.name, { args: t.args ?? [] });
      if (cap.error) { console.log(`skip: ${cap.error}`); index.push({ ...t, status: 'unprobeable', error: cap.error }); continue; }
      const manifest = toManifest(cap);
      const path = join(out, `${t.name.replace(/[@/]/g, '_')}.json`);
      await writeFile(path, JSON.stringify({ ...t, capturedAt: new Date().toISOString(), manifest }, null, 1));
      console.log(`${manifest.tools.length} tool(s) -> ${path}`);
      index.push({ ...t, status: 'ok', tools: manifest.tools.length, file: path });
    } catch (e) {
      console.log(`fail: ${String(e.message).split('\n')[0].slice(0, 90)}`);
      index.push({ ...t, status: 'failed', error: String(e.message).slice(0, 200) });
    }
  }
  await writeFile(join(out, 'index.json'), JSON.stringify(index, null, 1));
  const ok = index.filter((x) => x.status === 'ok').length;
  console.log(`\n${ok}/${index.length} captured -> ${out}/index.json`);
}
