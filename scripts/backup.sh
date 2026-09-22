#!/usr/bin/env bash
# Nightly encrypted backup of everything that is NOT on-chain:
#   data/monadguard.db  — signed receipts (JWS) + findings. The chain holds only hashes;
#                         lose this file and every receipt link dies.
#   .env                — MONADGUARD_PRF_HEX (attestor identity), PRIVATE_KEY, ADMIN_TOKEN
#   deployment.json
#
# Destination: a PRIVATE GitHub repo, pushed over SSH with a write deploy key that
# can touch only that repo. Archives are encrypted before they leave the server.
#
# One-time setup: see "Backups" in README.md.
#   cron:  15 3 * * *  /opt/monadguard/scripts/backup.sh >> /var/log/monadguard-backup.log 2>&1
#
# Restore:
#   openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass file:/root/.monadguard-backup.pass \
#     -in monadguard-YYYYMMDD-HHMM.tar.gz.enc | tar xz
set -euo pipefail

APP=${APP:-/opt/monadguard}
REPO=${BACKUP_REPO_DIR:-/opt/monadguard-backup}
PASS=${BACKUP_PASS_FILE:-/root/.monadguard-backup.pass}
KEY=${BACKUP_SSH_KEY:-/root/.ssh/monadguard_backup}
KEEP=${BACKUP_KEEP:-14}
STAMP=$(date -u +%Y%m%d-%H%M)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

[ -f "$PASS" ] || { echo "no passphrase file $PASS"; exit 1; }
[ -d "$REPO/.git" ] || { echo "backup repo not cloned at $REPO"; exit 1; }

# Consistent copy of a live SQLite DB (WAL mode): use the online backup API,
# never cp — cp can capture a half-written page.
DB=${MONADGUARD_DB:-$APP/data/monadguard.db}
cd "$APP"
node -e '
  const Database = require("better-sqlite3");
  new Database(process.argv[1], { readonly: true }).backup(process.argv[2])
    .then(() => console.log("db ok"))
    .catch((e) => { console.error(e.message); process.exit(1); });
' "$DB" "$TMP/monadguard.db"

mkdir -p "$TMP/bundle"
mv "$TMP/monadguard.db" "$TMP/bundle/"
cp "$APP/.env" "$TMP/bundle/env"
cp "$APP/deployment.json" "$TMP/bundle/" 2>/dev/null || true

OUT="monadguard-$STAMP.tar.gz.enc"
tar -C "$TMP/bundle" -czf - . \
  | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass "file:$PASS" -out "$REPO/$OUT"

# Prove it decrypts before trusting it.
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass "file:$PASS" -in "$REPO/$OUT" | tar tz >/dev/null
echo "archive ok: $OUT ($(du -h "$REPO/$OUT" | cut -f1))"

cd "$REPO"
ls -1t monadguard-*.tar.gz.enc | tail -n +$((KEEP + 1)) | xargs -r git rm -q --
git add "$OUT"
git -c user.name=monadguard-backup -c user.email=backup@monadguard.com commit -qm "backup $STAMP"
GIT_SSH_COMMAND="ssh -i $KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new" git push -q origin HEAD
echo "pushed $STAMP"
