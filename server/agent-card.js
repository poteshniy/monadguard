/**
 * ERC-8004 registration document, served at /.well-known/agent-registration.json.
 *
 * The Identity Registry stores a token URI and nothing else; everything a
 * reader learns about an agent comes from this file. So it has to be true, and
 * it has to keep being true — which is why it is generated from the running
 * configuration rather than committed as a static file that drifts.
 *
 * AGENT_ID is set after the mint (npm run agent:register prints it): the URI
 * has to resolve before you can register it, so the id can only be filled in
 * afterwards. Until then the registrations array is empty, which is honest.
 */
import * as chain from './chain.js';

const SITE = (process.env.BASE_URL ?? 'https://api.monadguard.com').replace(/\/$/, '').replace('://api.', '://');
const API = (process.env.BASE_URL ?? 'https://api.monadguard.com').replace(/\/$/, '');
const REGISTRY_8004 = process.env.AGENT_REGISTRY ?? '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432';

export const agentURI = `${SITE}/.well-known/agent-registration.json`;

export function agentCard() {
  const agentId = process.env.AGENT_ID ? Number(process.env.AGENT_ID) : null;
  return {
    type: 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1',
    name: 'MonadGuard',
    description:
      'Checks what an agent tool declares it can do — an MCP server\'s tools/list, a skill\'s text — for tool poisoning, hidden instructions, exfiltration and rug-pull patterns, then signs the verdict with a P-256 key and anchors it on Monad, where the contract verifies that signature through the P256VERIFY precompile. Every verdict is pinned to the hash of the exact manifest it covers, so a tool that changes after it was cleared no longer matches. A survey of the 40 most-downloaded MCP servers on npm is published with it. Local MCP server for agents: npx -y monadguard-mcp.',
    image: `${SITE}/mark.svg`,
    services: [
      { name: 'web', endpoint: SITE },
      { name: 'HTTP', endpoint: `${API}/registry`, skills: ['check-tool', 'read-trust-history'] },
      { name: 'GraphQL', endpoint: process.env.PUBLIC_GRAPHQL_URL ?? 'https://graphql.monadguard.com/v1/graphql', skills: ['read-trust-history'] },
    ],
    x402Support: false,
    active: true,
    registrations: agentId
      ? [{ agentId, agentRegistry: `eip155:${chain.CHAIN_ID}:${REGISTRY_8004}` }]
      : [],
    supportedTrust: ['reputation'],
    // What this agent will not do. These are decisions already made and already
    // enforced in the code, not aspirations — a reader can check each one.
    refuses: [
      'Anchoring a CRITICAL verdict on somebody\'s published package before a human has read the findings.',
      'Running a submitted server\'s code on request. Captures are run by hand, in a container with no network; a hosted endpoint is read over HTTP without executing anything.',
      'Fetching a URL on a visitor\'s behalf. This service is not a proxy into its own network.',
      'Calling a tool safe. A CLEAN verdict says the declared interface carried no known pattern, and static analysis never ran the code behind it.',
    ],
    trustRegistry: {
      name: 'MonadGuard ScanRegistry',
      chain: `eip155:${chain.CHAIN_ID}`,
      address: chain.REGISTRY,
    },
  };
}
