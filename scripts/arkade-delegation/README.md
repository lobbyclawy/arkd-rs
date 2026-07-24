# Arkade Delegation measurement harness

Instruments the six assumptions (A1-A6) behind the Arkade Delegation
column of the paper's comparison table. Replaces design-derivation with
measurement where a live regtest run or the pinned `ark-lib` can produce
a number.

Everything here pins **arkd v0.7.0**
(`fcb9f21ef69836e8ddadc2d070deb0c5be139336`) - the commit the paper
cites. The Go module pins the same `ark-lib` pseudo-version that arkd
v0.7.0's own `pkg/ark-cli/go.mod` requires, so the scripts produced are
byte-identical to that release.

## What it contains

| File | Role |
|------|------|
| `main.go` | Two subcommands: `script` (offline Tapscript + witness sizing, A1/A3) and `intentsize` (exact RegisterIntent wire size + witness decomposition from a captured intent row, A3) |
| `measure.sh` | End-to-end driver: boots arkd v0.7.0 on Nigiri, boards + renews a VTXO, captures arkd's intent store, and emits the A1-A4 table |
| `go.mod` | Pins `ark-lib` to the arkd v0.7.0 revision |

## Requirements

- `nigiri` running (`nigiri start`), `docker`, `go >= 1.23`, `python3`, `sqlite3`, `curl`
- An arkd checkout at v0.7.0. `measure.sh` clones the repo's
  `vendor/arkd` submodule and checks out the tag automatically; override
  with `ARKD_DIR=/path/to/arkd` (must already be at v0.7.0).

## Run

```bash
# Offline pieces only (no regtest needed) - A1 + the A3 witness delta:
cd scripts/arkade-delegation && go run . script

# Full live measurement (boots arkd on Nigiri, ~minutes on first build):
nigiri start
scripts/arkade-delegation/measure.sh --out arkade-delegation-results.md
```

`measure.sh` leaves the arkd stack running; tear it down with
`docker compose -f "$ARKD_DIR/docker-compose.regtest.yml" down -v`.

To size a specific captured intent by hand (the columns come straight
from arkd's `intent` table - `proof` and `message`):

```bash
go run . intentsize -proof-file proof.txt -message-file message.txt
```

## Assumption-by-assumption mapping

The paper derives the Arkade cells under A1-A6. Because arkd v0.7.0 has
**no native `delegate` primitive** (`git grep -i delegat` over the whole
tree returns nothing), the "delegate" of A2/A5/A6 is necessarily an
external, Fulmine-style always-on signer that holds the user's VTXO keys
and drives the ordinary client RPCs (`RegisterIntent`,
`SubmitSignedForfeitTxs`). What we can measure is the wire and on-chain
cost of those RPCs on real arkd; what we cannot measure without the
Fulmine delegate is its private storage (A6).

| # | Assumption | How this harness checks it | Result |
|---|------------|----------------------------|--------|
| A1 | Renewal Tapscript is a CLTV-gated 3-of-3 `CLTVMultisigClosure` over (user, delegate, ASP) | `go run . script` builds it with the pinned `ark-lib`; the type is on the forfeit/renewal path (`vtxo_script.go` `ForfeitClosures`, `offchain/tx.go`) | Confirmed - 108 B script; the type exists and is exercised on the settle path |
| A2 | Each renewal needs a per-batch `RegisterIntent` by the settling party | `measure.sh` drives two settles and counts rows in arkd's `intent`/`round` tables | Confirmed - 1 intent per round per participant |
| A3 | Per-renewal authorisation wire size is 64 B | `go run . intentsize` on the captured `intent.proof` decomposes the BIP-322 witness and computes the exact `RegisterIntentRequest` protobuf size | Signature is 64 B (SIGHASH_DEFAULT); **full RegisterIntent payload measured at ~1093 B**; the BIP-322 proof-of-funds signature is 65 B (SIGHASH_ALL) |
| A4 | A renewal folds into the next batch commitment with no own on-chain tx | `measure.sh` counts `type='commitment'` txs per round and per-block tx counts in the settle window | Confirmed - 1 shared commitment tx per round |
| A5 | The delegate (not the user) is the always-on party | code inspection of arkd v0.7.0 for any delegate primitive | No native delegate in arkd; the role is external (Fulmine) - the assumption describes that external component, not arkd |
| A6 | The delegate stores ~400 B per VTXO per active epoch | bounded from arkd's persisted per-VTXO state + what an external delegate must retain to rebuild each settle | Unmeasurable without Fulmine; ~400 B is a plausible order-of-magnitude for the minimal retained handle (tapscript tree dominates); the full serialized per-epoch intent is ~1 KB |

See `FC27-RESULTS.md` (repo root) section T2 for the full write-up and
the paper-delta list.
