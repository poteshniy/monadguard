/**
 * Runs INSIDE the sandbox container, with no network. Speaks MCP over stdio to
 * the installed server and prints {server, tools, resources, prompts} as JSON.
 *
 * Hand-rolled JSON-RPC rather than the SDK: one less dependency inside a
 * container whose whole job is to be disposable.
 */
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

const OUT = '/w/capture-result.json';
/** stdout is async once it is a pipe: console.log + process.exit truncates
 *  anything past ~64KB, which is most real tools/list payloads. Write a file. */
const emit = (obj) => { writeFileSync(OUT, JSON.stringify(obj)); process.exit(0); };

const pkg = process.argv[2];
const extraArgs = process.argv.slice(3);
const meta = JSON.parse(readFileSync(`/w/node_modules/${pkg}/package.json`, 'utf8'));
const binField = typeof meta.bin === 'string' ? meta.bin : Object.values(meta.bin ?? {})[0];
if (!binField) emit({ error: 'package has no bin' });

const child = spawn('node', [`/w/node_modules/${pkg}/${binField}`, ...extraArgs], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', NODE_ENV: 'production' },
});

let buf = '';
const pending = new Map();
let stderr = '';
child.stderr.on('data', (d) => { stderr += d; });
child.stdout.on('data', (d) => {
  buf += d;
  for (let i; (i = buf.indexOf('\n')) !== -1; ) {
    const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
    if (!line.startsWith('{')) continue;
    let msg; try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id != null && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  }
});

let id = 0;
const call = (method, params = {}) => new Promise((resolve) => {
  const myId = ++id;
  const t = setTimeout(() => { pending.delete(myId); resolve({ error: { message: 'timeout' } }); }, 15000);
  pending.set(myId, (m) => { clearTimeout(t); resolve(m); });
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: myId, method, params }) + '\n');
});
const notify = (method, params = {}) => child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');

const out = { package: pkg, version: meta.version };
try {
  const init = await call('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'monadguard-capture', version: '1.0.0' },
  });
  if (init.error) throw new Error(init.error.message);
  out.server = init.result?.serverInfo ?? {};
  out.instructions = init.result?.instructions ?? null;
  notify('notifications/initialized');
  for (const [key, method] of [['tools', 'tools/list'], ['resources', 'resources/list'], ['prompts', 'prompts/list']]) {
    const r = await call(method);
    out[key] = r.result?.[key] ?? [];
  }
} catch (e) {
  out.error = e.message;
  out.stderr = stderr.slice(-500);
}
child.kill('SIGKILL');
emit(out);
