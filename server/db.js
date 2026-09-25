/**
 * Write-side cache. The chain plus Envio is the source of truth; this exists
 * so POST /scan can answer with a receipt before the anchor tx confirms, and
 * so a failed anchor can be retried without re-scanning.
 *
 * Ported from AgentTrust src/db.js — same better-sqlite3 pattern, new schema
 * (tools / scans keyed on toolId + contentHash instead of one flat hash table).
 */
import Database from 'better-sqlite3';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';

const DB_PATH = process.env.MONADGUARD_DB ?? './data/monadguard.db';
mkdirSync(dirname(DB_PATH), { recursive: true });

export const db = new Database(DB_PATH);
db.exec(readFileSync(new URL('./schema.sql', import.meta.url), 'utf8'));

// Additive migrations: CREATE TABLE IF NOT EXISTS silently skips new columns on
// an existing file, which is exactly how a schema change becomes a 3am bug.
const columns = new Set(db.prepare('PRAGMA table_info(scans)').all().map((c) => c.name));
for (const col of ['sig_r', 'sig_s']) {
  if (!columns.has(col)) db.exec(`ALTER TABLE scans ADD COLUMN ${col} TEXT`);
}

const stmts = {
  upsertTool: db.prepare(`
    INSERT INTO tools (tool_id, kind, name, origin, first_seen)
    VALUES (@tool_id, @kind, @name, @origin, @first_seen)
    ON CONFLICT(tool_id) DO UPDATE SET name = excluded.name, origin = excluded.origin`),

  insertScan: db.prepare(`
    INSERT INTO scans (tool_id, content_hash, verdict, score, findings_json,
                       receipt_jws, receipt_hash, receipt_uri, created_at, anchor_state)
    VALUES (@tool_id, @content_hash, @verdict, @score, @findings_json,
            @receipt_jws, @receipt_hash, @receipt_uri, @created_at, 'pending')
    ON CONFLICT(receipt_hash) DO NOTHING`),

  byReceipt: db.prepare('SELECT * FROM scans WHERE receipt_hash = ?'),
  byTool: db.prepare('SELECT * FROM scans WHERE tool_id = ? ORDER BY created_at DESC LIMIT ?'),
  tool: db.prepare('SELECT * FROM tools WHERE tool_id = ?'),
  pending: db.prepare("SELECT * FROM scans WHERE anchor_state IN ('pending','failed') ORDER BY created_at LIMIT ?"),
  queued: db.prepare(`
    SELECT * FROM scans
    WHERE anchor_state IN ('queued','failed') AND sig_r IS NOT NULL
    ORDER BY created_at LIMIT ?`),
  saveSig: db.prepare("UPDATE scans SET sig_r = ?, sig_s = ?, anchor_state = 'queued' WHERE receipt_hash = ?"),
  setState: db.prepare('UPDATE scans SET anchor_state = ? WHERE receipt_hash = ?'),
  markAnchor: db.prepare('UPDATE scans SET anchor_tx = ?, anchor_block = ?, anchor_state = ? WHERE receipt_hash = ?'),
  // Every identity this node has seen under one origin. An anchored one first:
  // a tool somebody scanned locally and never anchored is a weaker answer than
  // one that exists on chain.
  byOrigin: db.prepare(`
    SELECT t.tool_id, t.kind, t.name, t.origin,
           (SELECT COUNT(*) FROM scans s WHERE s.tool_id = t.tool_id AND s.anchor_state = 'confirmed') AS anchored
    FROM tools t
    WHERE lower(t.origin) = lower(?) AND (? IS NULL OR t.kind = ?)
    ORDER BY anchored DESC, t.first_seen ASC
    LIMIT 10`),

  recent: db.prepare(`
    SELECT t.tool_id, t.kind, t.name, t.origin,
           s.verdict, s.score, s.created_at, s.anchor_tx, s.anchor_state
    FROM tools t
    JOIN scans s ON s.id = (SELECT id FROM scans WHERE tool_id = t.tool_id ORDER BY created_at DESC LIMIT 1)
    ORDER BY s.created_at DESC LIMIT ?`),

  counts: db.prepare(`
    SELECT COUNT(*) AS scans,
           SUM(anchor_state = 'confirmed') AS anchored,
           SUM(anchor_state IN ('queued','failed')) AS awaiting,
           COUNT(DISTINCT tool_id) AS tools
    FROM scans`),
};

export const upsertTool = (t) => stmts.upsertTool.run({ ...t, first_seen: Math.floor(Date.now() / 1000) });
export const insertScan = (s) => stmts.insertScan.run(s);
export const getScan = (receiptHash) => stmts.byReceipt.get(receiptHash);
export const getTool = (toolId) => stmts.tool.get(toolId);
export const scansForTool = (toolId, limit = 50) => stmts.byTool.all(toolId, limit);
export const pendingScans = (limit = 100) => stmts.pending.all(limit);
export const queuedScans = (limit = 25) => stmts.queued.all(limit);
export const queueScan = (receiptHash, sig) => stmts.saveSig.run(sig.r, sig.s, receiptHash);
export const setState = (receiptHash, state) => stmts.setState.run(state, receiptHash);
export const markAnchored = (receiptHash, tx, block, state = 'confirmed') =>
  stmts.markAnchor.run(tx, block, state, receiptHash);
export const recentTools = (limit = 25) => stmts.recent.all(limit);
export const toolsByOrigin = (origin, kind = null) => stmts.byOrigin.all(origin, kind, kind);
export const stats = () => stmts.counts.get();

const ext = {
  put: db.prepare(`INSERT OR IGNORE INTO external_receipts
    (receipt_hash, jws, tool_id, attestor_x, attestor_y, findings_json, created_at)
    VALUES (@receipt_hash, @jws, @tool_id, @attestor_x, @attestor_y, @findings_json, @created_at)`),
  get: db.prepare('SELECT * FROM external_receipts WHERE receipt_hash = ?'),
  grant: db.prepare('INSERT INTO faucet_grants (address, ip, tx, created_at) VALUES (?, ?, ?, ?)'),
  granted: db.prepare('SELECT * FROM faucet_grants WHERE address = ?'),
  grantsSince: db.prepare('SELECT COUNT(*) AS n FROM faucet_grants WHERE created_at > ?'),
  grantsByIpSince: db.prepare('SELECT COUNT(*) AS n FROM faucet_grants WHERE ip = ? AND created_at > ?'),
};
export const putExternalReceipt = (r) => ext.put.run({ ...r, created_at: Math.floor(Date.now() / 1000) });
export const getExternalReceipt = (hash) => ext.get.get(hash);
export const faucetGranted = (address) => ext.granted.get(address.toLowerCase());
export const faucetGrantsSince = (ts) => ext.grantsSince.get(ts).n;
export const faucetGrantsByIpSince = (ip, ts) => ext.grantsByIpSince.get(ip, ts).n;
export const recordFaucetGrant = (address, ip, tx) => ext.grant.run(address.toLowerCase(), ip, tx, Math.floor(Date.now() / 1000));
