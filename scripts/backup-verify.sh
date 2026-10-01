#!/usr/bin/env bash
# npm run backup:verify
#
# A backup nobody has restored is a hope, not a backup. This does the restore
# for real: takes the newest archive, decrypts it, opens the database inside it,
# and compares what is in there against the database the API is serving right
# now. It touches nothing live — the archive is unpacked into a temp directory
# that goes away on exit, and the live DB is opened read-only.
#
# Nothing secret is printed. The passphrase is passed to openssl as a file, the
# restored .env is checked for presence and key names only, never contents.
#
# Exit codes: 0 all good · 1 something is wrong and is named in the output.
set -euo pipefail

APP=${APP:-/opt/monadguard}
REPO=${BACKUP_REPO_DIR:-/opt/monadguard-backup}
PASS=${BACKUP_PASS_FILE:-/root/.monadguard-backup.pass}
MAX_AGE_HOURS=${BACKUP_MAX_AGE_HOURS:-36}
DB=${MONADGUARD_DB:-$APP/data/monadguard.db}

fail() { echo "FAIL  $*"; exit 1; }
ok()   { echo "ok    $*"; }

[ -f "$PASS" ] || fail "no passphrase file at $PASS — the nightly job cannot be running"
[ -d "$REPO/.git" ] || fail "no backup repo at $REPO"

LATEST=$(ls -1t "$REPO"/monadguard-*.tar.gz.enc 2>/dev/null | head -1 || true)
[ -n "$LATEST" ] || fail "no archives in $REPO — nothing has ever been backed up"

# Age. A backup that stopped three weeks ago looks exactly like a working one
# until you check the date.
AGE_S=$(( $(date -u +%s) - $(date -u -r "$LATEST" +%s) ))
AGE_H=$(( AGE_S / 3600 ))
if [ "$AGE_H" -gt "$MAX_AGE_HOURS" ]; then
  fail "newest archive is ${AGE_H}h old (limit ${MAX_AGE_HOURS}h) — $(basename "$LATEST"). The cron job has stopped."
fi
ok "newest archive ${AGE_H}h old: $(basename "$LATEST") ($(du -h "$LATEST" | cut -f1))"

COUNT=$(ls -1 "$REPO"/monadguard-*.tar.gz.enc | wc -l)
ok "$COUNT archive(s) retained"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass "file:$PASS" -in "$LATEST" \
  | tar -C "$TMP" -xz || fail "the archive does not decrypt or does not unpack — the passphrase file may have changed since it was written"
ok "decrypts and unpacks"

[ -s "$TMP/monadguard.db" ] || fail "no database inside the archive"
[ -s "$TMP/env" ] || fail "no .env inside the archive — a restore would come up with no attestor identity"

# The identity is the part that cannot be rebuilt from the chain. Check the keys
# are present by name; never print a value.
for k in MONADGUARD_PRF_HEX PRIVATE_KEY; do
  grep -q "^${k}=" "$TMP/env" || fail "the archived .env has no ${k} — the attestor identity is not in this backup"
done
ok "archived .env carries the attestor identity (names only, values not read)"

# Open both databases and compare. The restored one is allowed to be behind the
# live one — it is a snapshot — but it must not be empty, and it must not be
# ahead, which would mean it is from somewhere else entirely.
cd "$APP"
node -e '
const Database = require("better-sqlite3");
const open = (p) => new Database(p, { readonly: true, fileMustExist: true });
const count = (db, t) => { try { return db.prepare(`SELECT COUNT(*) n FROM ${t}`).get().n; } catch { return null; } };
const [restored, live] = [open(process.argv[1]), open(process.argv[2])];
const rows = ["tools", "scans"].map((t) => ({ table: t, restored: count(restored, t), live: count(live, t) }));
let bad = 0;
for (const r of rows) {
  if (r.restored === null) { console.log(`FAIL  the restored database has no ${r.table} table`); bad++; continue; }
  if (r.restored === 0 && r.live > 0) { console.log(`FAIL  ${r.table}: restored 0, live ${r.live} — the backup is empty`); bad++; continue; }
  if (r.restored > r.live) { console.log(`FAIL  ${r.table}: restored ${r.restored} > live ${r.live} — this archive is not from this server`); bad++; continue; }
  const lag = r.live - r.restored;
  console.log(`ok    ${r.table}: ${r.restored} restored, ${r.live} live (${lag} added since)`);
}
process.exit(bad ? 1 : 0);
' "$TMP/monadguard.db" "$DB" || fail "the restored database does not line up with the live one"

# The receipts are the whole point: the chain holds hashes, this file holds the
# documents those hashes address. A row with no JWS restores to a dead link.
node -e '
const Database = require("better-sqlite3");
const db = new Database(process.argv[1], { readonly: true });
// length() rather than a comparison against an empty string: inside a
// single-quoted shell argument there is no way to write one, and in SQLite
// double quotes are an identifier, not a literal — "" parses as a column
// named nothing, which is how this check first shipped broken.
const { n, missing } = db.prepare("SELECT COUNT(*) n, SUM(CASE WHEN receipt_jws IS NULL OR length(receipt_jws) = 0 THEN 1 ELSE 0 END) missing FROM scans").get();
if (!n) { console.log("FAIL  no scans in the restored database"); process.exit(1); }
if (missing) { console.log(`FAIL  ${missing} of ${n} restored scans have no signed receipt — those links would be dead after a restore`); process.exit(1); }
console.log(`ok    all ${n} restored scans carry their signed receipt`);
' "$TMP/monadguard.db" || fail "the restored receipts are not intact"

echo
echo "RESTORE DRILL PASSED — this archive would bring the service back."
