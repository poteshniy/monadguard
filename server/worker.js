/**
 * Batch anchor worker.
 *
 * Drains signed-but-unanchored scans out of SQLite and pushes them through
 * `anchorScanBatch` in one transaction.
 *
 * Why this exists, in order of importance:
 *
 *   1. PRF ceremonies need user verification and are not configurable. The
 *      browser derives once, signs N receipts in memory, and hands them over.
 *      Anchoring them one tx at a time would mean N wallet prompts. Batching is
 *      what makes the passkey flow usable at all.
 *   2. A failed anchor stops being a lost scan. State goes back to `failed`,
 *      the next tick retries it with backoff, and nothing has to be re-scanned.
 *   3. Volume. "Monad is fast" is an empty claim in a submission unless the demo
 *      actually pushes throughput at it.
 *
 * Run alongside the API:  npm run worker
 * One pass and exit:      npm run worker -- --once
 */
import './env.js';
import * as db from './db.js';
import * as chain from './chain.js';
import { loadAttestor } from './keys.js';
import { anchorDigest, signDigest } from './receipt.js';

const BATCH_MAX = Number(process.env.BATCH_MAX ?? 25);
const INTERVAL_MS = Number(process.env.WORKER_INTERVAL_MS ?? 15_000);
const MAX_BACKOFF_MS = Number(process.env.WORKER_MAX_BACKOFF_MS ?? 5 * 60_000);
const ONCE = process.argv.includes('--once');

const key = loadAttestor({ allowDevKey: process.env.NODE_ENV !== 'production' });
let backoff = 0;

/**
 * Rows that arrived from the browser already carry (sig_r, sig_s). Rows that
 * don't are only signable here if this node holds a key — the headless path.
 */
function toScanInput(row, attestorAddress) {
  let r = row.sig_r;
  let s = row.sig_s;

  if (!r || !s) {
    if (!key) return null;
    const digest = anchorDigest({
      chainId: chain.CHAIN_ID, registry: chain.REGISTRY, attestor: attestorAddress,
      toolId: row.tool_id, contentHash: row.content_hash,
      verdict: row.verdict, score: row.score, receiptHash: row.receipt_hash,
    });
    ({ r, s } = signDigest(digest, key.privateKey));
  }

  return {
    toolId: row.tool_id,
    contentHash: row.content_hash,
    receiptHash: row.receipt_hash,
    verdict: row.verdict,
    score: row.score,
    r,
    s,
    receiptURI: row.receipt_uri ?? '',
  };
}

export async function drainOnce() {
  if (!chain.REGISTRY) return { skipped: 'no registry address' };

  const { account } = chain.wallet();
  const rows = [...db.queuedScans(BATCH_MAX), ...(key ? db.pendingScans(BATCH_MAX) : [])]
    .filter((row, i, all) => all.findIndex((x) => x.receipt_hash === row.receipt_hash) === i)
    .slice(0, BATCH_MAX);

  if (rows.length === 0) return { anchored: 0 };

  const inputs = [];
  const included = [];
  for (const row of rows) {
    const input = toScanInput(row, account.address);
    if (input) { inputs.push(input); included.push(row.receipt_hash); }
  }
  if (inputs.length === 0) return { anchored: 0, waitingForSignatures: rows.length };

  for (const h of included) db.setState(h, 'sent');

  try {
    const res = await chain.anchorScanBatch(inputs);
    const state = res.status === 'success' ? 'confirmed' : 'failed';
    for (const h of included) db.markAnchored(h, res.hash, res.block, state);
    if (state === 'confirmed') backoff = 0;
    return { anchored: inputs.length, tx: res.hash, block: res.block, status: res.status };
  } catch (e) {
    // One bad signature reverts the whole batch, so a repeated failure must not
    // wedge the queue forever — see the poison-row note below.
    for (const h of included) db.setState(h, 'failed');
    backoff = Math.min(backoff === 0 ? INTERVAL_MS : backoff * 2, MAX_BACKOFF_MS);
    throw e;
  }
}

/**
 * A row whose signature is genuinely invalid will fail every batch it lands in
 * and take good rows down with it. After `POISON_AFTER` consecutive whole-batch
 * failures, fall back to anchoring one at a time so the bad row is isolated and
 * everything else gets through.
 */
const POISON_AFTER = Number(process.env.WORKER_POISON_AFTER ?? 3);
let consecutiveFailures = 0;

async function drainOneByOne() {
  const { account } = chain.wallet();
  const rows = db.queuedScans(BATCH_MAX);
  let ok = 0;
  for (const row of rows) {
    const input = toScanInput(row, account.address);
    if (!input) continue;
    try {
      const res = await chain.anchorScan({
        toolId: input.toolId, contentHash: input.contentHash, verdict: input.verdict,
        score: input.score, receiptHash: input.receiptHash, receiptURI: input.receiptURI,
        key, sig: { r: input.r, s: input.s },
      });
      db.markAnchored(row.receipt_hash, res.hash, res.block, res.status === 'success' ? 'confirmed' : 'failed');
      ok++;
    } catch (e) {
      db.markAnchored(row.receipt_hash, null, null, 'poison');
      console.error(`[worker] poison row ${row.receipt_hash}: ${e.shortMessage ?? e.message}`);
    }
  }
  return ok;
}

async function tick() {
  try {
    const res = await drainOnce();
    consecutiveFailures = 0;
    if (res.anchored) console.log(`[worker] anchored ${res.anchored} in ${res.tx} (block ${res.block})`);
    else if (res.skipped) console.log(`[worker] idle: ${res.skipped}`);
  } catch (e) {
    consecutiveFailures++;
    console.error(`[worker] batch failed (${consecutiveFailures}): ${e.shortMessage ?? e.message}`);
    if (consecutiveFailures >= POISON_AFTER) {
      console.error('[worker] falling back to one-by-one to isolate the bad row');
      const ok = await drainOneByOne();
      console.log(`[worker] isolated pass anchored ${ok}`);
      consecutiveFailures = 0;
      backoff = 0;
    }
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(`[worker] batch=${BATCH_MAX} interval=${INTERVAL_MS}ms registry=${chain.REGISTRY ?? '(none)'}`);
  await tick();
  if (!ONCE) {
    const loop = async () => {
      await tick();
      setTimeout(loop, INTERVAL_MS + backoff);
    };
    setTimeout(loop, INTERVAL_MS);
  }
}
