#!/usr/bin/env bash
# scripts/arkade-delegation/measure.sh - Arkade Delegation measurement
# protocol for the paper's Table 1 assumptions (A1-A6).
#
# Drives arkd v0.7.0 (fcb9f21ef69836e8ddadc2d070deb0c5be139336) on
# Nigiri regtest using the ark CLI bundled in the arkd image, captures
# the real RegisterIntent payloads from arkd's intent store, and counts
# the on-chain transactions produced per settlement round. The
# assumption-by-assumption mapping is documented in README.md next to
# this script.
#
# Requirements:
#   - nigiri running (nigiri start)
#   - docker, go, python3, sqlite3, curl
#   - an arkd checkout at v0.7.0. Defaults to cloning the vendor/arkd
#     submodule into a temp dir; override with ARKD_DIR=/path/to/arkd
#     (must already be checked out at v0.7.0).
#
# Usage: scripts/arkade-delegation/measure.sh [--out PATH]
#
# The arkd regtest stack is left running afterwards; stop it with:
#   docker compose -f "$ARKD_DIR/docker-compose.regtest.yml" down -v

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

ADMIN_AUTH="Authorization: Basic YWRtaW46YWRtaW4="   # admin:admin, arkd default
ARK_PASSWORD="password"
CAPTURE_DIR="$(mktemp -d)"
trap 'rm -rf "$CAPTURE_DIR"' EXIT

log() { echo "[measure] $*" >&2; }

admin_get()  { curl -s -H "$ADMIN_AUTH" "http://localhost:7070$1"; }
admin_post() { curl -s -X POST -H "$ADMIN_AUTH" -H 'Content-Type: application/json' -d "$2" "http://localhost:7070$1"; }
ark() { docker exec -t arkd ark "$@"; }

# ─── 0. Preconditions ────────────────────────────────────────────────
if ! nigiri rpc getblockcount >/dev/null 2>&1; then
  echo "measure.sh: nigiri not reachable; run 'nigiri start' first" >&2
  exit 1
fi

if [ -z "${ARKD_DIR:-}" ]; then
  ARKD_DIR="$(mktemp -d)/arkd"
  log "cloning vendor/arkd submodule to $ARKD_DIR (v0.7.0)"
  git clone -q --no-hardlinks "$REPO_ROOT/vendor/arkd" "$ARKD_DIR"
  git -C "$ARKD_DIR" checkout -q v0.7.0
fi
PIN="$(git -C "$ARKD_DIR" rev-parse HEAD)"
log "arkd checkout: $PIN"
if [ "$PIN" != "fcb9f21ef69836e8ddadc2d070deb0c5be139336" ]; then
  log "WARNING: arkd is not at the paper's pinned commit"
fi

# ─── 1. arkd regtest stack ───────────────────────────────────────────
log "starting arkd + arkd-wallet containers (first build takes minutes)"
docker compose -f "$ARKD_DIR/docker-compose.regtest.yml" up -d --build >&2

# ─── 2. ASP wallet bootstrap ─────────────────────────────────────────
log "waiting for arkd admin API"
until admin_get /v1/admin/wallet/status | grep -q initialized; do sleep 2; done

if admin_get /v1/admin/wallet/status | grep -q '"initialized":false'; then
  SEED=$(admin_get /v1/admin/wallet/seed | python3 -c "import json,sys; print(json.load(sys.stdin)['seed'])")
  admin_post /v1/admin/wallet/create "{\"seed\":\"$SEED\",\"password\":\"$ARK_PASSWORD\"}" >/dev/null
  sleep 1
  admin_post /v1/admin/wallet/unlock "{\"password\":\"$ARK_PASSWORD\"}" >/dev/null
elif admin_get /v1/admin/wallet/status | grep -q '"unlocked":false'; then
  admin_post /v1/admin/wallet/unlock "{\"password\":\"$ARK_PASSWORD\"}" >/dev/null
fi

log "waiting for ASP wallet sync"
until admin_get /v1/admin/wallet/status | grep -q '"synced":true'; do sleep 2; done

ASP_ADDR=""
while [ -z "$ASP_ADDR" ]; do
  ASP_ADDR=$(admin_get /v1/admin/wallet/address | python3 -c "import json,sys; print(json.load(sys.stdin).get('address',''))" 2>/dev/null || true)
  [ -z "$ASP_ADDR" ] && sleep 1
done
log "funding ASP wallet ($ASP_ADDR)"
nigiri faucet "$ASP_ADDR" >&2
nigiri rpc --generate 1 >/dev/null

# ─── 3. Client setup + boarding ──────────────────────────────────────
log "initializing ark client"
ark init --server-url localhost:7070 --password "$ARK_PASSWORD" \
  --network regtest --explorer http://chopsticks:3000 >&2 || true

BOARDING_ADDR=$(ark receive | python3 -c "import json,sys; print(json.load(sys.stdin)['boarding_address'])")
log "funding boarding address ($BOARDING_ADDR)"
nigiri faucet "$BOARDING_ADDR" >&2
nigiri rpc --generate 1 >/dev/null
sleep 2

H0=$(nigiri rpc getblockcount)

# ─── 4. Settle #1: board into a VTXO (registers intent #1) ───────────
log "settle #1 (boarding utxo -> vtxo)"
ark settle --password "$ARK_PASSWORD" >&2
nigiri rpc --generate 1 >/dev/null
sleep 2

# ─── 5. Settle #2: renew the VTXO (registers intent #2) ──────────────
log "settle #2 (vtxo renewal)"
ark settle --password "$ARK_PASSWORD" >&2
nigiri rpc --generate 1 >/dev/null
sleep 2

H1=$(nigiri rpc getblockcount)

# ─── 6. Capture arkd's intent store ──────────────────────────────────
log "capturing arkd data dir"
docker cp arkd:/app/data "$CAPTURE_DIR/arkd-data" >&2
DB=$(find "$CAPTURE_DIR/arkd-data" -name '*.db' -path '*sqlite*' | head -1)
[ -z "$DB" ] && DB=$(find "$CAPTURE_DIR/arkd-data" -name '*.db' | head -1)
if [ -z "$DB" ]; then
  echo "measure.sh: could not locate arkd sqlite db in captured data dir" >&2
  exit 3
fi
log "sqlite db: $DB"

emit() {
  echo "## Arkade Delegation measurements (arkd v0.7.0 @ ${PIN:0:8}, Nigiri regtest)"
  echo
  echo "Blocks scanned: $H0 -> $H1"
  echo

  # A2/A4: rounds, their intents, and their on-chain txs.
  echo "### Rounds, intents, and on-chain transactions (A2, A4)"
  echo
  echo '```'
  sqlite3 "$DB" "SELECT r.id, r.ended, r.failed,
    (SELECT count(*) FROM intent i WHERE i.round_id = r.id) AS intents,
    (SELECT count(*) FROM tx t WHERE t.round_id = r.id AND t.type='commitment') AS commitment_txs
    FROM round r ORDER BY r.starting_timestamp;"
  echo '```'
  echo
  echo "On-chain tx count per block in the settle window (coinbase included):"
  echo '```'
  for h in $(seq "$H0" "$H1"); do
    HASH=$(nigiri rpc getblockhash "$h")
    NTX=$(nigiri rpc getblock "$HASH" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['tx']))")
    echo "block $h: $NTX tx"
  done
  echo '```'
  echo

  # A3: exact RegisterIntent wire sizes from the captured rows.
  echo "### RegisterIntent payloads (A3)"
  echo
  i=0
  sqlite3 -separator '|' "$DB" "SELECT id FROM intent;" | while read -r INTENT_ID; do
    i=$((i+1))
    sqlite3 "$DB" "SELECT proof   FROM intent WHERE id='$INTENT_ID';" > "$CAPTURE_DIR/proof.$i"
    sqlite3 "$DB" "SELECT message FROM intent WHERE id='$INTENT_ID';" > "$CAPTURE_DIR/message.$i"
    echo "#### intent $i (id ${INTENT_ID:0:12})"
    echo '```'
    (cd "$HERE" && go run . intentsize -proof-file "$CAPTURE_DIR/proof.$i" -message-file "$CAPTURE_DIR/message.$i")
    echo '```'
    echo
  done

  # A1 (+ A3 delegate-path delta): script construction with pinned ark-lib.
  echo "### Delegated-renewal Tapscript (A1)"
  echo
  echo '```'
  (cd "$HERE" && go run . script)
  echo '```'
}

if [ -n "$OUT" ]; then
  emit > "$OUT"
  log "wrote $OUT"
else
  emit
fi
