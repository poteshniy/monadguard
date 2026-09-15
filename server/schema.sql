-- Local mirror. Source of truth is the chain + Envio; this is the write-side
-- cache so /scan can respond before the anchor tx confirms.
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS tools (
  tool_id      TEXT PRIMARY KEY,        -- 0x… bytes32, from toolid.mjs
  kind         TEXT NOT NULL,           -- 'mcp' | 'skill'
  name         TEXT NOT NULL,
  origin       TEXT NOT NULL,
  first_seen   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  tool_id       TEXT NOT NULL REFERENCES tools(tool_id),
  content_hash  TEXT NOT NULL,
  verdict       INTEGER NOT NULL,       -- 0..3
  score         INTEGER NOT NULL,       -- 0..100 risk
  findings_json TEXT NOT NULL,          -- rule hits from scanner/
  receipt_jws   TEXT NOT NULL,          -- full signed receipt (jws.js)
  receipt_hash  TEXT NOT NULL,          -- keccak256(receipt payload)
  receipt_uri   TEXT,
  sig_r         TEXT,                   -- P-256 anchor signature over anchorDigest(...)
  sig_s         TEXT,                   -- browser-supplied on the passkey path
  created_at    INTEGER NOT NULL,
  anchor_tx     TEXT,                   -- NULL until anchored
  anchor_block  INTEGER,
  anchor_state  TEXT NOT NULL DEFAULT 'pending'  -- pending|queued|sent|confirmed|failed
                                        -- pending: no signature yet (browser hasn't signed)
                                        -- queued:  signed, waiting for the batch worker

);
CREATE INDEX IF NOT EXISTS idx_scans_tool ON scans(tool_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_anchor ON scans(anchor_state, created_at) WHERE anchor_state != 'confirmed';
CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_receipt ON scans(receipt_hash);
