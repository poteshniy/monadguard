#!/usr/bin/env node
/**
 * MonadGuard as an MCP server: the registry, inside the agent, as a tool.
 *
 *   claude mcp add monadguard -- npx -y monadguard-mcp
 *   { "mcpServers": { "monadguard": { "command": "npx", "args": ["-y", "monadguard-mcp"] } } }
 *
 * Two tools, both read-only and both offline-safe (they only talk to the public
 * registry):
 *   check_tool     — what the chain says about a tool, before connecting to it
 *   scan_manifest  — scan a tools/list payload you already have, no network write
 *
 * Nothing here anchors anything. Writing to the registry needs an attestor key,
 * which an agent running someone else's prompt should not be holding.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { check, toolId, VERDICTS, DEFAULTS } from './index.js';

const API = process.env.MONADGUARD_API ?? DEFAULTS.api;

const TOOLS = [
  {
    name: 'check_tool',
    description: 'Check an MCP server or agent skill against the MonadGuard on-chain trust registry BEFORE connecting to it. Returns every attestor\'s own latest verdict (CLEAN / WARN / CRITICAL / UNKNOWN), the risk score and the transaction that recorded it. UNKNOWN means nobody has scanned it — not that it is safe.',
    inputSchema: {
      type: 'object',
      properties: {
        origin: { type: 'string', description: 'Where the tool comes from: "npm:@scope/package", a repo URL or a server URL' },
        name: { type: 'string', description: 'The name the server declares for itself, e.g. "memory-server", if you know it. Leave it out and the registry resolves the origin — do not guess it from the package name' },
        kind: { type: 'string', enum: ['mcp', 'skill'], description: 'Defaults to mcp' },
      },
      required: ['origin'],
    },
  },
  {
    name: 'scan_manifest',
    description: 'Scan an MCP manifest (the tools/list payload) for tool poisoning, hidden instructions, exfiltration wording and rug-pull patterns. Use it on a manifest you already hold — for example one a server just sent you. Returns a verdict, a risk score and the individual findings with fixes. Nothing is written on-chain.',
    inputSchema: {
      type: 'object',
      properties: {
        manifest: { type: 'object', description: 'The tools/list result: { name, tools: [{ name, description, inputSchema }] }' },
        name: { type: 'string', description: 'Optional name to report it under' },
      },
      required: ['manifest'],
    },
  },
];

const text = (o) => ({ content: [{ type: 'text', text: typeof o === 'string' ? o : JSON.stringify(o, null, 2) }] });

const server = new Server({ name: 'monadguard', version: '0.2.1' }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params;

  if (name === 'check_tool') {
    const tool = { kind: args.kind ?? 'mcp', origin: args.origin, ...(args.name ? { name: args.name } : {}) };
    let r;
    try {
      r = await check(tool);
    } catch (e) {
      // The registry being unreachable is not a clean bill of health. Say so
      // in the answer instead of throwing, so the agent reads it as a result.
      return text({
        verdict: 'UNKNOWN',
        known: false,
        error: e.message,
        advice: 'The registry could not be reached, so nothing is known about this tool right now. Treat it as unverified.',
        toolId: tool.name ? toolId(tool) : null,
      });
    }
    return text({
      verdict: r.verdict,
      risk: r.score,
      known: r.known,
      advice: r.verdict === 'CLEAN' ? 'A registered attestor cleared this exact version. Check the timestamp before relying on it.'
        : r.verdict === 'UNKNOWN'
          ? (!r.known && r.candidates?.length
            // The caller pinned a name that does not exist on chain. Do not
            // answer about a different identity — say which one it would be.
            ? `Nothing is known under the name "${args.name}". The registry knows ${r.candidates[0].origin} as "${r.candidates[0].name}" — ask again with that name, or with no name at all, if that is the server you mean.`
            : 'Nobody has scanned this tool. Treat it as unverified, not as safe.')
          : 'At least one attestor flagged this tool. Read the findings before connecting.',
      attestors: r.attestors,
      toolId: r.toolId,
      // Which identity this answer is actually about, when the caller only knew
      // the package: the declared name is part of the identity, so say it.
      ...(r.resolved ? { declaredName: r.resolved.name, resolvedBy: 'origin' } : {}),
      registry: r.toolId ? `https://monadguard.com/#tool/${r.toolId}` : 'https://monadguard.com',
      source: r.source,
    });
  }

  if (name === 'scan_manifest') {
    // The scanner lives server-side so the ruleset stays one implementation.
    const m = args.manifest;
    const r = await fetch(`${API}/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ kind: 'mcp', name: args.name ?? m?.name ?? 'pasted-manifest', origin: 'mcp-client:local', manifest: m }),
      signal: AbortSignal.timeout(15000),
    });
    const j = await r.json();
    if (!r.ok) return text({ error: j.error ?? `scan failed (${r.status})` });
    return text({
      verdict: VERDICTS[j.verdict] ?? 'UNKNOWN',
      risk: j.score,
      gate: j.gate === 'act' ? 'safe to connect' : 'do not connect',
      findings: (j.findings ?? []).map((f) => ({ id: f.id, severity: f.severity, what: f.desc, where: f.field, fix: f.recommendation })),
      receipt: j.receipt?.uri,
      note: 'Signed but not anchored: writing to the registry needs an attestor key.',
      toolId: toolId({ kind: 'mcp', name: args.name ?? m?.name ?? 'pasted-manifest', origin: 'mcp-client:local' }),
    });
  }

  return text({ error: `unknown tool: ${name}` });
});

await server.connect(new StdioServerTransport());
