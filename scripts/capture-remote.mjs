#!/usr/bin/env node
/**
 * Capture a HOSTED MCP server's tools/list over HTTP.
 *
 *   npm run capture:remote -- https://example.com/mcp
 *   npm run capture:remote -- https://example.com/mcp --name their-server
 *
 * The npm path in capture.mjs installs and runs third-party code, which is why
 * it lives in a network-less container. This one runs nothing: it opens a
 * streamable-HTTP MCP session, asks for the tool list, and closes. The only
 * thing crossing the boundary is JSON we then treat as hostile input — which is
 * the whole job of the scanner anyway.
 *
 * Two limits are enforced because the response is a stranger's: a hosted server
 * can answer with as much as it likes, and a scanner that happily ingests 400MB
 * of "tool descriptions" is a denial of service with extra steps.
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

const MAX_TOOLS = 2000;
const MAX_BYTES = 4 * 1024 * 1024;

/** A hosted server is named by its URL; the declared name still decides toolId. */
export const originFor = (url) => `mcp:${String(url).replace(/\/+$/, '')}`;

export async function captureRemote(url, { timeoutMs = 30000 } = {}) {
  const target = new URL(url);
  if (target.protocol !== 'https:' && target.hostname !== '127.0.0.1' && target.hostname !== 'localhost') {
    throw new Error(`refusing plain http to a remote host: ${url}`);
  }

  const client = new Client({ name: 'monadguard-capture', version: '0.2.1' });
  // Streamable HTTP is the current transport; SSE is the older one a few hosted
  // servers still speak. Try both before calling a server unprobeable.
  let transport = 'streamable-http';
  try {
    await client.connect(new StreamableHTTPClientTransport(target), { timeout: timeoutMs });
  } catch (e) {
    try {
      await client.connect(new SSEClientTransport(target), { timeout: timeoutMs });
      transport = 'sse';
    } catch {
      throw new Error(`handshake failed (${String(e.message ?? e).slice(0, 160)})`);
    }
  }

  try {
    const info = client.getServerVersion?.() ?? {};
    const caps = client.getServerCapabilities?.() ?? {};
    const { tools = [] } = await client.listTools({}, { timeout: timeoutMs });
    if (tools.length > MAX_TOOLS) throw new Error(`${tools.length} tools — refusing (cap ${MAX_TOOLS})`);

    // Resources and prompts are part of the attack surface too, but plenty of
    // servers declare neither and answer the request with an error.
    const soft = async (fn, key) => { try { return (await fn())[key] ?? []; } catch { return []; } };
    const resources = caps.resources ? await soft(() => client.listResources({}, { timeout: timeoutMs }), 'resources') : [];
    const prompts = caps.prompts ? await soft(() => client.listPrompts({}, { timeout: timeoutMs }), 'prompts') : [];

    const cap = {
      url: target.href,
      transport,
      server: { name: info.name, version: info.version },
      instructions: client.getInstructions?.() ?? undefined,
      tools, resources, prompts,
    };
    const size = Buffer.byteLength(JSON.stringify(cap));
    if (size > MAX_BYTES) throw new Error(`response is ${(size / 1e6).toFixed(1)}MB — refusing (cap ${MAX_BYTES / 1e6}MB)`);
    return cap;
  } finally {
    await client.close().catch(() => {});
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { mkdir, writeFile } = await import('node:fs/promises');
  const { join } = await import('node:path');
  const argv = process.argv.slice(2);
  const flag = (n, d) => { const i = argv.indexOf(`--${n}`); return i === -1 ? d : argv[i + 1]; };
  const url = argv.find((a) => /^https?:\/\//.test(a));
  if (!url) { console.error('usage: npm run capture:remote -- https://host/mcp [--name label] [--out capture/remote]'); process.exit(1); }
  const out = flag('out', 'capture/remote');

  process.stdout.write(`${url}  `);
  let cap;
  try {
    cap = await captureRemote(url);
  } catch (e) {
    console.log(`unprobeable: ${e.message}`);
    process.exit(1);
  }

  const manifest = {
    name: cap.server?.name ?? flag('name') ?? new URL(url).hostname,
    version: cap.server?.version,
    ...(cap.instructions ? { description: cap.instructions } : {}),
    tools: cap.tools,
    ...(cap.resources?.length ? { resources: cap.resources } : {}),
    ...(cap.prompts?.length ? { prompts: cap.prompts } : {}),
  };
  const slug = (flag('name') ?? new URL(url).hostname + new URL(url).pathname).replace(/[^a-z0-9._-]+/gi, '_');
  await mkdir(out, { recursive: true });
  const path = join(out, `${slug}.json`);
  await writeFile(path, JSON.stringify({
    name: manifest.name, origin: originFor(url), url: cap.url, transport: cap.transport,
    capturedAt: new Date().toISOString(), manifest,
  }, null, 1));
  console.log(`${cap.transport} · ${manifest.tools.length} tool(s) -> ${path}`);
}
