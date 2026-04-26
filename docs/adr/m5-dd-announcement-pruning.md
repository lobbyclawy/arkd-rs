# ADR M5-DD: Round announcement pruning policy

- **Status:** Proposed
- **Date:** 2026-04-25
- **Milestone:** CV-M5 (Stealth Addresses)
- **Drives:** #552 → constrains #556, #557, #560 → informs #558
- **Affects:** operator-side announcement storage and the wallet-restore UX;
  no on-chain changes; no consensus-relevant changes; transparent paths
  untouched (#520 parity gate).

## Context

A confidential VTXO that pays a stealth address (#553/#554) is unspendable
to anyone who cannot derive the recipient's one-time pubkey, and whether a
particular wallet *is* the recipient is itself confidential — only the
holder of the matching `scan_sk` can decide. The mechanism that lets a
recipient learn "this round paid me" without the operator learning who
they are is the **round announcement**: a per-round list of
`(vtxo_id, ephemeral_pubkey)` tuples that scanning clients pull and walk
locally with their `scan_sk` (per ADR-0003 / #555). Each tuple is two
strings on the wire (a `txid:vout` and a 33-byte compressed point hex),
totalling ~110 bytes when serialised over gRPC.

The announcement set is the index. It is the only artefact a freshly
restored wallet can consult to discover historical incoming stealth
payments — the recipient's wallet was offline when the round closed and
never received any direct notification, so the only reconstruction path
is "fetch every announcement since my birthday and try to decrypt".

The decision is therefore a balance between two opposing pressures:

- **Recovery** — a user who has been offline for an arbitrary period MUST
  be able to restore their wallet from seed and rediscover every stealth
  VTXO they ever received (#560). If announcements vanish, those VTXOs
  become irrecoverable from seed alone (the on-chain VTXO output exists
  but the wallet cannot identify it as theirs without the `ephemeral_pk`
  → `scan_sk` ECDH that yields the one-time spend key).
- **Storage growth** — at realistic load the announcement set grows
  monotonically with no in-protocol upper bound. The operator pays the
  storage cost in perpetuity. Sized below in "Storage growth analysis".

This ADR fixes the retention scheme, the numerical bounds, the
checkpoint mechanism wallets can pin against, the wallet-restore semantics
when a client is offline past the retention window, and the gRPC-surface
contract that #556 / #557 / #560 must implement.

The ADR also resolves the open question raised in #557's task list:
*"Auth: not required (announcements leak no more than the on-chain tree
root already does) — confirm in ADR `m5-dd-pruning`."* — see "Privacy and
auth" below.

## Requirements

- **Bounded operator storage**: the steady-state announcement table size
  MUST be bounded by a published, configurable retention parameter and
  MUST NOT grow without limit under honest load.
- **Recoverability invariant**: for any VTXO `V` that is *unspent and not
  yet expired*, the announcement that introduced `V` MUST be retrievable
  by a scanning client. Pruning an unspent VTXO's announcement is a
  recovery hazard and MUST NOT happen on the happy path.
- **Birthday-bounded restore**: a wallet that supplies a `birthday`
  (round id or a numeric round height) within the retention window MUST
  successfully complete a restore. A wallet whose birthday falls *before*
  the retention window MUST receive a typed, descriptive error rather
  than a silent partial restore.
- **Checkpoint pinning**: a wallet that has previously scanned up to some
  cursor MUST be able to pin that cursor and resume, without re-scanning
  from genesis on every restart, even if pruning has advanced the lower
  bound of the operator's table.
- **Atomic pruning**: pruning MUST NOT race with announcement insertion
  on round commit (#556). The pruning job operates on closed rounds
  whose retention has expired and never on rounds being assembled.
- **Public read surface**: `GetRoundAnnouncements` (#557) is unauthenticated.
  This ADR documents the rationale and pins the semantics so the
  decision is not re-litigated downstream.
- **Operator config**: retention parameters MUST be operator-tunable
  via `config.toml` and surfaced through Prometheus metrics so capacity
  planning is observable, not guessed.
- **Backwards compatibility**: the announcement format is additive. No
  existing transparent code path consults announcements; #520 parity
  gate is unaffected.

## Storage growth analysis

A round announcement on the wire is `(round_id, vtxo_id, ephemeral_pubkey)`.
Encoded for storage in `dark-live-store` (the SQL row-major form #556
defines):

| Column            | Type           | Size (typical)     |
|-------------------|----------------|--------------------|
| `round_id`        | `TEXT` (uuid)  | 36 B               |
| `vtxo_id`         | `TEXT` (`txid:vout`) | ~67 B (64 hex + ":N") |
| `ephemeral_pubkey`| `BYTEA` (33)   | 33 B (raw) / 66 B (hex) |
| `created_at`      | `TIMESTAMPTZ`  | 8 B                |
| **Logical row**   |                | ~145 B             |
| With page overhead and one btree index over `(round_id, vtxo_id)` and one over `created_at`, the on-disk cost lands at **~256 B per announcement** on Postgres. |

We do not assume disk compression beyond Postgres' default TOAST behaviour
(announcements are short and won't be TOASTed; the index tuples dominate
overhead).

Round-rate scenarios:

| Profile        | Rounds/hr | Confidential outputs/round | Announcements/yr     | Storage/yr (no prune) | Cumulative @ 5 yr |
|----------------|-----------|---------------------------|----------------------|-----------------------|-------------------|
| Bootstrap      | 12        | 50                        | ~5.3 M               | ~1.3 GB               | ~6.6 GB           |
| Steady-state   | 60        | 200                       | ~105 M               | ~26 GB                | ~130 GB           |
| Stress         | 120       | 500                       | ~525 M               | ~130 GB               | ~650 GB           |
| Aspirational   | 360       | 1000                      | ~3.15 B              | ~790 GB               | ~3.95 TB          |

The "Steady-state" and "Stress" rows are the working assumption for
operator capacity planning; the "Bootstrap" row matches the load expected
in the first 6–12 months post-launch. Storage cost in the operator's
dollar terms is not the binding constraint — the **index size and
insert/scan latency** are. At the Stress row's 525 M rows, the
`(round_id, vtxo_id)` btree alone is ~55 GB, large enough that
`GetRoundAnnouncements` cursor-paginated scans will start to cold-cache-miss
on commodity SSDs and the announcement table risks becoming the slowest
component in the round commit path.

Pruning does not have to be aggressive to flatten this curve — a 12-month
retention window at the Stress row caps the steady-state table at
~130 GB rather than letting it grow without bound, and the index size
follows. Pruning IS necessary; the question this ADR resolves is *what*
to prune and *when*.

## Options Considered

The issue description suggests three retention frames. The space is wider
than the three; we evaluate four to make the boundaries of the chosen
scheme clearer.

### Option 1 — Keep forever

The operator never deletes an announcement. The table grows monotonically
with the round count for the lifetime of the deployment.

- **Recovery**: perfect. Any wallet, with any birthday, can restore
  fully. Even a wallet whose owner was offline for ten years recovers
  every received VTXO that is still unspent.
- **Storage growth**: unbounded. At the Stress row this is ~130 GB/yr
  forever. After 5 years the table outweighs the rest of the operator's
  database; the announcement table becomes the dominant operational cost.
- **Index latency**: degrades gracefully if the operator partitions the
  table by round_id range; degrades sharply otherwise. Cursor-paginated
  scans for the most-recent rounds remain hot regardless.
- **Privacy**: announcements published 5 years ago are still scannable
  today. A passive observer that mirrored every announcement has the
  same view as the operator. This is *not* a privacy regression — the
  only thing announcements expose is the `(vtxo_id, ephemeral_pubkey)`
  pair, which is also derivable from the on-chain round commitment by
  anyone willing to walk the round tree (see "Privacy and auth").
- **Operator failure mode**: gradual degradation, never sudden. There is
  no point at which a wallet that *was* recoverable becomes irrecoverable.
- **Verdict**: simplest semantics; storage cost trends to dominant; no
  recovery cliff. Strong default if cost were not a concern.

### Option 2 — Prune when all referenced VTXOs are spent or expired

For each announcement `A = (round_id, vtxo_id, ephemeral_pubkey)`, retain
`A` for as long as the VTXO it references is unspent and unexpired.
Prune `A` once `V` is either consumed (its nullifier has been observed
in a subsequent round) or its tree has rolled past the operator-side
expiry timelock and been swept.

- **Recovery**: imperfect. A wallet whose owner has been offline since
  before *all* their VTXOs were spent or expired cannot rediscover those
  spent/expired VTXOs from announcements. For *unspent* VTXOs, recovery
  is perfect — which is the only case the user actually needs to
  recover, since spent VTXOs have no claimable balance.
- **Storage growth**: bounded by the active VTXO set + a tail of
  recently-consumed announcements waiting on the next prune cycle. At
  steady-state the active confidential VTXO set is roughly the in-flight
  liquidity; the announcement table size is therefore proportional to
  the unspent confidential VTXO set, not to the cumulative round count.
- **Operational complexity**: high. Pruning needs to consult the
  nullifier set (#525), the expiry sweep records (#549), and the round
  tree to decide whether `V` is still referenceable. Four moving parts
  and the prune transaction has to grab read-locks across all of them.
- **Failure mode under bug**: severe. A bug that prunes an announcement
  for a still-unspent VTXO permanently breaks restore for that wallet —
  the on-chain VTXO is still there, but no scanning client can rediscover
  it from seed. Recovery requires an out-of-band re-publish, which the
  operator may or may not have the data to do (the announcement table
  is the source of truth; once pruned, the `ephemeral_pubkey` is lost
  unless retained in a separate audit log).
- **Privacy**: announcements for spent VTXOs disappear, which slightly
  shrinks the public surface. This is a marginal property because spent
  VTXOs are themselves on-chain (their nullifiers are public), so the
  privacy delta vs. Option 1 is negligible.
- **Verdict**: storage-optimal but operationally fragile and recovery-
  brittle. Rejected — see "Decision".

### Option 3 — Fixed-window retention (chosen)

The operator retains an announcement for a configurable window after
the round closed and prunes it unconditionally once the window expires.
Recovery beyond the window is supported via a separate, slow-path
**archival store** that holds the same `(round_id, vtxo_id, ephemeral_pubkey)`
tuples in a compressed, append-only form on cheaper storage (e.g.
object storage with cold-tier pricing).

- **Recovery**: perfect within the retention window (fast path).
  Recovery beyond the window is supported via the archival store
  (slow path; minutes-to-hours rather than seconds, but still
  recoverable). Recovery is unconditional — a wallet that asks for a
  birthday before the archival horizon receives a structured error
  with remediation guidance, but no in-window birthday ever fails.
- **Storage growth**: live (hot) table is bounded by the retention window
  in rounds; archival store grows but at ~10× lower per-byte cost and is
  not in the critical path of round commit.
- **Operational complexity**: low. Pruning is a single-table operation:
  delete rows where `round_id` corresponds to a closed round older than
  `retention_rounds`. Archival is an append-only batch job that runs on
  pruned rows and writes them to the archival sink.
- **Failure mode under bug**: contained. A bug in the prune job at worst
  prunes too aggressively; the rows are still in the archival store, so
  recovery shifts from fast-path to slow-path but is not lost. A bug that
  prunes *and* fails to archive is the recovery hazard; mitigated by
  archive-before-prune ordering.
- **Privacy**: identical to Option 1 over the long term — the archival
  store is also publicly readable (#557 is unauthenticated). Pruning
  the *hot* store has no privacy effect.
- **Verdict**: recovery is preserved unconditionally, storage is
  bounded, and the prune job is a single-table delete. Adopted —
  see "Decision".

### Option 4 — Per-key opt-in retention

Each scan key publishes a "subscription" with the operator that pins a
retention window for announcements that ECDH-match it. Announcements
that don't match any subscribed scan key are pruned aggressively.

- **Recovery**: perfect for subscribed keys; broken for unsubscribed
  keys (e.g. fresh restore from a seed that never subscribed).
- **Privacy**: catastrophic regression. The whole point of the stealth-
  address scheme is that the operator does not know who is receiving
  what. A subscription endpoint that asks "is this scan key yours?"
  re-introduces the link the protocol exists to break, even if the
  subscription protocol is zero-knowledge — every additional bit of
  metadata the operator holds about scan keys is a privacy loss.
- **Verdict**: violates the milestone's privacy goals. Rejected
  unconditionally.

### Evaluation matrix

| Criterion                              | Opt 1 (forever)    | Opt 2 (prune-when-spent) | Opt 3 (windowed + archival) | Opt 4 (per-key) |
|----------------------------------------|--------------------|--------------------------|------------------------------|-----------------|
| Bounded operator storage                | **No**             | Yes                      | Yes                          | Yes             |
| Recovery for offline-since-genesis      | Yes                | **No** (for spent VTXOs) | Yes (slow-path)              | **No** (unsubscribed) |
| Recovery for unspent VTXOs always       | Yes                | Yes                      | Yes                          | **No** (unsubscribed) |
| Prune-job operational simplicity        | n/a                | **Complex** (4-way join) | Simple (single-table)        | Complex         |
| Prune-job blast radius on bug           | n/a                | **High** (silent unspendability) | Low (archival catches)       | High            |
| Privacy regression vs. baseline         | None               | Marginal positive        | None                         | **Severe**      |
| Operator-tunable                        | n/a                | No                       | Yes                          | Yes             |
| Restoration UX surfaces a clear error   | n/a (always works) | Hard (which VTXOs?)      | Easy (cursor < horizon)      | Easy            |
| Index size growth                       | Linear in time     | Bounded by active set    | Bounded by window            | Variable        |
| Compatible with `birthday` parameter    | Trivially          | Hard (no horizon)        | Yes (window + archival)      | Yes             |

## Decision

**Adopt Option 3 — tiered hot/archival retention with a fixed retention
window.** Numerical bounds:

- `RETENTION_WINDOW_ROUNDS = 52_560` rounds.
  At the Steady-state row's 60 rounds/hr this is exactly **365 days**
  of rolling retention. The window is configured as a round count rather
  than a time so a low-traffic deployment that closes 12 rounds/hr
  (Bootstrap row) gets a *5-year* effective window — the lower the
  round rate, the more headroom restore has. Operators MAY override
  via `[stealth.announcements] retention_rounds = N` in `config.toml`.
  The default MUST be 52_560.

- `ARCHIVAL_HORIZON_ROUNDS = 525_600` rounds.
  Approximately **10 years** at Steady-state. Beyond this horizon, even
  the archival store may be pruned. Recovery for a wallet whose
  birthday is older than the archival horizon is **not supported** and
  the client receives a typed `RestoreError::BirthdayBeforeArchivalHorizon`
  with remediation guidance ("contact the operator out-of-band; your
  wallet may still hold spendable VTXOs but they are not discoverable
  from seed alone via this operator's archival store"). The archival
  horizon is configurable; default is 525_600.

- `MIN_RETENTION_FLOOR_ROUNDS = 4_320` rounds (~30 days at Steady-state).
  Operators MUST NOT configure `retention_rounds` below this floor. A
  smaller window breaks the wallet-restore UX assumption that "a wallet
  offline for a typical vacation" recovers without invoking archival.
  The crate MUST refuse to start if the configured value is below the
  floor; refusal is a hard error, not a warning.

- `PRUNE_BATCH_ROUNDS = 64` rounds.
  Pruning runs on a fixed cadence (default every `prune_interval_secs =
  3600`, configurable). Each prune cycle deletes announcements for at
  most 64 rounds' worth of expired data, archives those rows
  beforehand, and commits as a single transaction. Smaller batches
  bound the lock window held against `round_announcements` so concurrent
  round-commit inserts (#556) are not stalled.

- **Order of operations on prune (mandatory)**: archive first, delete
  second, in two separate transactions. The archival sink commit MUST
  succeed before the live-store DELETE runs. If archival fails, the
  prune cycle aborts and retries on the next interval. There is no
  delete-without-archive path.

- **Hot-store layout** (live, queryable in O(ms)):
  Postgres table `round_announcements(round_id TEXT, vtxo_id TEXT,
  ephemeral_pubkey BYTEA, created_at TIMESTAMPTZ)`, primary key
  `(round_id, vtxo_id)`, secondary index on `created_at` for the prune
  scan. Defined in #556.

- **Archival-store layout** (cold, queryable in O(s)):
  Object-storage bucket with one Parquet file per `archival_window =
  retention_rounds / 8` rounds (4 files per year at default config),
  schema `(round_id STRING, vtxo_id STRING, ephemeral_pubkey BINARY)`,
  zstd-compressed. The bucket prefix is configurable via
  `[stealth.archival] bucket_uri = "s3://..."` or
  `[stealth.archival] local_path = "/var/lib/dark/announcements/"` for
  single-node deployments. The archival store is also exposed through
  `GetRoundAnnouncements` (#557) but with a higher latency budget
  (server reads Parquet on-demand and streams; clients receive a
  streaming response identical in shape to the hot path).

- **`GetRoundAnnouncements` contract** (#557): unauthenticated, public.
  The endpoint MUST transparently span the hot and archival stores.
  If the requested `round_id_start` is older than the archival horizon,
  the endpoint MUST return a structured gRPC error
  (`FAILED_PRECONDITION` with a `BirthdayBeforeArchivalHorizon` detail)
  rather than silently returning a partial result. Clients (#558,
  #560) MUST surface this as `RestoreError::BirthdayBeforeArchivalHorizon`
  to the caller.

### Why a window, not "until all VTXOs spent"

Option 2 is storage-optimal but ties the retention decision to data
that lives in three other repositories (nullifier set, sweep records,
round tree). The prune cycle becomes a four-way join under live read
contention from the round commit path. A bug — anywhere in any of the
four — that erroneously concludes a VTXO is "spent or expired" silently
breaks restore for the affected wallet *forever*: the announcement is
gone, the on-chain VTXO is still there, the wallet has no path back to
the `ephemeral_pubkey` it needs to derive the one-time spend key.

Option 3's prune cycle reads one column (`round_id`'s round-close time)
and writes to one table. The blast radius of a prune-job bug is bounded
to "rows go to archival earlier than expected"; the live-store correctness
of the announcement set is unaffected. We pay for that simplicity in
storage — the live table holds announcements for closed-and-spent VTXOs
for up to a year — but at ~256 B per row and a year-bounded table, the
storage cost (Steady-state: ~26 GB) is operational rather than
existential.

### Why an archival horizon at all

The aspirational endpoint of "wallets offline for a decade" is real but
exists in the long tail. Setting the archival horizon at 10 years
captures every realistic restore scenario (vacation, hardware loss,
hospitalisation, generational transfer) while leaving the operator
the option to drop archival data older than that. A wallet that has
been offline for >10 years is in the same operational class as a wallet
that lost its seed: *some* recovery is possible (for example via direct
operator outreach with the scan_pk and a hand-walk of historical round
trees) but it is not on the standard automated path.

## Checkpoint mechanism

Wallets pin a **scan checkpoint** so that restart, crash, or normal
shutdown doesn't force a re-scan from genesis. This is the answer to
the issue's question *"is there an 'announcement checkpoint' clients
can pin so they don't have to download from genesis?"*

A scan checkpoint is the cursor returned by `GetRoundAnnouncements`'s
last successful page, persisted in the wallet's local state:

```text
ScanCheckpoint {
    last_scanned_round_id:    String,        // exclusive lower bound on next scan
    last_scanned_vtxo_id:     String,        // exclusive lower bound within the round
    last_scanned_at:          UnixTimestamp, // for staleness detection
    operator_endpoint:        Url,           // pin the endpoint so a wallet
                                              // pointed at a different operator
                                              // re-scans (the announcement set
                                              // is operator-specific)
}
```

The cursor format is the `(round_id, vtxo_id)` pair already exposed by
the indexer trait (`RoundRepository::list_round_announcements` takes
`cursor: Option<(&str, &str)>`, treated as exclusive — see #557).
Reusing the existing cursor avoids a parallel "checkpoint id" type and
keeps the wallet's persistence schema flat.

**Restart semantics**:

1. On wallet open, load the latest `ScanCheckpoint` from local state.
2. Call `GetRoundAnnouncements(cursor: Some((last_round, last_vtxo)))`.
3. Stream announcements, scanning each, advancing the cursor.
4. On graceful shutdown or every `checkpoint_flush_interval_secs = 60`
   seconds (whichever fires first), persist the latest cursor.
5. On the operator's response with `BirthdayBeforeArchivalHorizon` for a
   live cursor (operator advanced the archival horizon past where the
   wallet last scanned — only happens if the wallet was offline > 10
   years), surface a typed error to the user; do not silently advance.

**Why pin the endpoint**: announcements are operator-specific. A user
who switches operator mid-restore must re-scan from their birthday
against the new operator. Pinning prevents a silent under-scan if the
user's CLI config changed between sessions.

**Cross-restart correctness**: a checkpoint persisted at `(R, V)` means
"every announcement up to and including `(R, V)` has been scanned and
its decryption result has been committed to the local VTXO store". The
flush interval is a rate-limit for disk writes; on crash, the wallet
re-scans from the last persisted cursor, which means a small window of
announcements may be re-decrypted on the next start. Re-decryption is
idempotent (the `(amount, blinding)` recovered is the same) and the
local VTXO store deduplicates on `vtxo_id`, so re-scan is correct, just
wasted work. The window is bounded by `checkpoint_flush_interval_secs`.

## Wallet restore semantics

### In-window birthday (happy path)

Wallet supplies `birthday = round_id_or_height` such that the requested
range falls entirely inside the live retention window. The operator
serves the entire range from the hot store. The restore completes in
seconds-to-minutes depending on round count and CPU (each announcement
requires one ECDH per local scan key per ADR-0003; cost is dominated by
secp256k1 scalar mult).

### Beyond-window birthday but within archival horizon

Wallet supplies `birthday` older than `RETENTION_WINDOW_ROUNDS` but
newer than `ARCHIVAL_HORIZON_ROUNDS`. The operator serves the older
prefix from the archival store and the newer suffix from the hot
store, transparently to the client. Restore latency increases (Parquet
scan adds seconds-to-minutes per archival window file) but completes
correctly. The client SHOULD render a progress indicator that
distinguishes "cold-storage scan" from "hot-storage scan" so the user
understands why a one-year-old wallet restores faster than a five-
year-old one.

### Beyond archival horizon

Wallet supplies `birthday` older than `ARCHIVAL_HORIZON_ROUNDS`. The
operator returns gRPC `FAILED_PRECONDITION` with detail
`BirthdayBeforeArchivalHorizon { current_horizon_round: <id> }`. The
client's `restore_from_seed` (#560) MUST surface this as
`RestoreError::BirthdayBeforeArchivalHorizon` with the structured
field so the CLI can render:

```
Cannot restore from birthday R_0: this operator's announcement
archive begins at R_H (current horizon).

Recovery options:
  (a) Restart the restore with --birthday R_H (any VTXOs you
      received between R_0 and R_H will not be discovered from
      seed; if you have the on-chain VTXO ids saved separately
      you can import them directly via `ark-cli vtxo import`).
  (b) Contact the operator out-of-band with your scan_pk; they
      may be able to walk a deeper archive (operator policy).
```

The error MUST be typed and structured; a string-only error is
non-actionable and does not satisfy #560's acceptance criterion 2
(birthday tests).

### No birthday supplied

Wallet does not supply a birthday. The client defaults to scanning the
entire archival horizon. This is a user-friendly default but
expensive (~10 years of archival reads at the default horizon). The
CLI MUST surface a one-time confirmation prompt the first time a
no-birthday restore is invoked: *"You did not supply a birthday. The
restore will scan ~10 years of historical announcements. This will
take roughly N minutes / read M GB. Continue? [y/N]"*. The exact
wording lives with #560; this ADR mandates the *substance*: a no-
birthday restore must not silently consume an archival-store-sized
budget.

### Birthday after the most recent round

Wallet supplies a `birthday` newer than the operator's tip. The
operator returns an empty stream. The client treats this as
"no historical scan needed" and proceeds to live tip-following (#558).
This is a normal case for fresh wallets and does not require a warning.

## Privacy and auth

`GetRoundAnnouncements` is **public, unauthenticated**. The original
issue text flagged this as an open question; this ADR closes it.

Reasoning:

- The on-chain round-commitment tx (#540) is public. Anyone can walk
  the round tree, extract the leaf set, and read the
  `(vtxo_id, ephemeral_pubkey)` of every confidential leaf. The
  announcement endpoint exposes the same data in a more efficient
  shape — it is an indexing convenience, not a privacy boundary.
- Authenticating the endpoint would force every restoring wallet to
  acquire credentials before scanning, which is incompatible with
  "restore from seed alone". The credential acquisition channel
  itself becomes a metadata leak (the operator learns an IP /
  identity that wants to scan).
- An unauthenticated public endpoint also serves third-party
  block-explorer integrations (for example, the operator-agnostic
  scan service some wallet vendors run) without bespoke credential
  flows.

The decision: announcements are public, the gRPC method is unauthenticated,
caching headers and ETags are populated by the REST gateway (per #557
acceptance criterion 3) on the assumption that any HTTP intermediary
may cache the response without violating any user's privacy.

This decision constrains downstream work — see "Cross-cutting" below.

## Operator config surface

Operators tune retention via `config.toml`:

```toml
[stealth.announcements]
# Number of rounds the live announcement table retains before
# pruning to archival. Default 52_560 (~365 days at 60 rounds/hr).
# Hard floor: 4_320 (the crate refuses to start below this value).
retention_rounds = 52_560

# How often the prune cycle runs.
prune_interval_secs = 3_600

# Maximum number of round-buckets pruned per cycle. Bounds the
# lock window held against the announcement table.
prune_batch_rounds = 64

[stealth.archival]
# One of `bucket_uri` or `local_path` MUST be set if pruning is
# enabled. If neither is set, the crate refuses to start (refusing
# to delete announcements without an archival sink).
bucket_uri = "s3://my-operator-archive/announcements/"
# local_path = "/var/lib/dark/announcements/"

# Number of rounds the archival store retains before deleting.
# Default 525_600 (~10 years at 60 rounds/hr). Set to 0 to retain
# archival forever.
archival_horizon_rounds = 525_600

# Compression codec for archival Parquet files.
codec = "zstd"
```

Prometheus metrics exported by `dark-live-store` (per #556 acceptance
criterion 3):

- `announcements_live_rows_total` — gauge, current row count in the
  hot table.
- `announcements_archival_rows_total` — gauge, current row count
  across all archival files.
- `announcements_prune_runs_total{result="ok"|"err"}` — counter.
- `announcements_prune_archived_rows_total` — counter, rows
  successfully archived since process start.
- `announcements_prune_deleted_rows_total` — counter, rows deleted
  from the hot table since process start. Steady-state, this should
  equal `announcements_prune_archived_rows_total` minus retries.
- `announcements_horizon_round_id` — gauge label, the operator's
  current archival horizon round id (`Beyond archival horizon` errors
  reference this).

## Consequences

### Positive

- **Bounded steady-state storage.** The hot announcement table is
  bounded by `retention_rounds`. At default config and the
  Steady-state row, the live table tops out at ~26 GB; the archival
  store grows linearly but at ~10× lower per-byte cost and is not on
  the round-commit critical path.
- **Recovery is unconditional within 10 years.** Wallets restore
  successfully for any in-archival-horizon birthday. The error path
  for older birthdays is structured and actionable rather than a
  silent partial restore.
- **One-table prune.** The prune job reads `round_id` and writes the
  archival sink; no cross-repository joins, no read-locks across the
  nullifier set or sweep records. Operationally cheap and easy to
  reason about under contention.
- **Checkpoint pinning is the same cursor as `GetRoundAnnouncements`.**
  No parallel checkpoint type to maintain in the wallet schema; the
  cursor is already the indexer trait's cursor format. Restarts
  resume at last-flushed-cursor with bounded re-scan.
- **Public read endpoint matches the on-chain leak.** No new privacy
  surface vs. the round commitment; auth is not required and
  third-party caching is permitted.

### Negative / follow-ups

- **Storage is paid in two tiers.** The operator runs Postgres for the
  hot store and an archival sink (S3 / local) for the cold store.
  Single-node deployments using `local_path` get the storage savings
  but inherit the local-disk failure domain for the cold store; the
  follow-up issue **[FU-ANN-ARCHIVE-REPLICATE]** is appropriate if a
  replicated archival sink is needed.
- **Restore for >10-year offline wallets is not on the seed-alone
  path.** A wallet whose birthday predates the archival horizon
  cannot restore from seed against this operator without out-of-band
  data (the on-chain VTXO ids). Documented in the wallet-birthday UX
  doc per #552's acceptance criteria.
- **The cold-store query path is slower.** Beyond-window birthday
  restores read Parquet files on demand; throughput is bounded by the
  bucket's per-object retrieval characteristics. A 5-year-old restore
  at the Stress row reads ~5 archival files per archival window
  config, on the order of 10s of seconds end-to-end. Acceptable for
  the recovery path but not the hot scan path.
- **Two stores means two query paths in `GetRoundAnnouncements`.**
  The endpoint must handle the boundary case where a single request
  spans both stores. #557 is responsible for stitching the streams;
  this ADR fixes the contract that the boundary is invisible to the
  client.
- **Operator-specific announcements.** A wallet pinned to operator A
  cannot transparently restore from operator B. Multi-operator
  topologies (post-launch concern, out of scope for CV-M5) need a
  separate strategy. **[FU-ANN-MULTI-OP]** is the follow-up tracking
  issue.
- **Compression footprint depends on data heterogeneity.** Parquet
  + zstd compresses the announcement stream at ~3× ratio at the
  schema's small-string profile (uuid + txid + 33-byte pubkey). The
  ratio is informational; the archival horizon math assumes the
  uncompressed row size for safety.

### Cross-cutting — constraints on downstream issues

These are not suggestions; they are requirements for this ADR's
soundness. Any deviation must reopen this ADR before landing.

#### #556 (round announcement storage and indexing) MUST

- Implement the `round_announcements` Postgres table with primary key
  `(round_id, vtxo_id)` and a secondary index on `created_at`
  (for prune scans).
- Implement the prune job as a fixed-cadence background task
  parameterised by `retention_rounds`, `prune_interval_secs`,
  `prune_batch_rounds`. The job MUST respect the
  `MIN_RETENTION_FLOOR_ROUNDS` floor at startup and refuse to run
  if the configured value is below it.
- Implement archive-before-delete ordering in two transactions. The
  archival commit MUST succeed before the live-store DELETE runs.
- Export the Prometheus metrics enumerated in "Operator config
  surface" above. The label and metric names are pinned by this
  ADR; renaming reopens it.
- Insert announcements as part of the round-commit transaction
  (atomic with VTXO insertion per the issue's acceptance criterion 1),
  so a partial round commit cannot leave announcements behind or
  forward of the VTXOs they reference.

#### #556 MUST NOT

- Couple the prune decision to the nullifier set or sweep records.
  The prune job is a single-table read on `round_id` (or the
  closed-round timestamp index). Cross-repository joins are
  explicitly out of scope for this ADR.
- Delete an announcement without a successful archival commit for
  the same row. The archive-before-delete invariant is mandatory.

#### #557 (`GetRoundAnnouncements` gRPC endpoint) MUST

- Be unauthenticated. The proto definition MUST NOT include any
  per-request auth metadata, and the gRPC server MUST NOT reject
  unauthenticated callers.
- Span the hot and archival stores transparently. Clients receive
  a single ordered stream of `(round_id, vtxo_id, ephemeral_pubkey)`
  triples regardless of which store backs each row.
- Return `FAILED_PRECONDITION` with a typed
  `BirthdayBeforeArchivalHorizon { current_horizon_round: String }`
  detail when `round_id_start` is older than the archival horizon.
  Clients MUST be able to extract the structured field; this ADR
  forbids string-only errors for this case.
- Honour the cursor's exclusivity semantic per the `RoundRepository`
  trait (`cursor: Option<(&str, &str)>` is the exclusive lower
  bound). The cursor format is the same `(round_id, vtxo_id)` tuple
  used by the trait; clients pin it as their `ScanCheckpoint`.
- Populate caching headers / ETags on the REST gateway when the
  request range falls entirely inside the archival store (immutable
  data; safe to cache for the archival horizon). For ranges that
  include the hot store, the response is non-cacheable (rounds are
  still being inserted).

#### #557 MUST NOT

- Introduce per-key auth or per-key quotas. The endpoint is uniform
  across callers. Rate-limiting at the IP / network layer is fine
  (operator policy) but per-key gating is a privacy regression
  (Option 4) that this ADR rejects.

#### #558 (background stealth scanning loop) MUST

- Persist the scan cursor every `checkpoint_flush_interval_secs`
  (default 60 s) or at clean shutdown, whichever fires first. The
  cursor is the `(round_id, vtxo_id)` exclusive lower bound from
  the last fully-processed page.
- Pin the cursor against the operator endpoint URL so a config
  change to a different operator triggers a fresh scan from
  birthday rather than reusing a stale cursor.
- Surface `BirthdayBeforeArchivalHorizon` from a live cursor (rare:
  only fires if the wallet was offline >10 years and the operator's
  horizon advanced past the cursor) as a structured error to the
  caller; do not silently restart from the new horizon.

#### #560 (wallet restore) MUST

- Default to scanning from `birthday` if supplied; if not supplied,
  prompt the user before scanning the full archival horizon.
- Return `RestoreError::BirthdayBeforeArchivalHorizon` with the
  operator's current horizon round id when the operator returns
  `FAILED_PRECONDITION` for that case. The CLI MUST render the
  remediation guidance specified in "Wallet restore semantics".
- Cache the cursor per-restore-session so `Ctrl-C` mid-restore
  resumes from the last flushed cursor (issue acceptance criterion
  3, "resume test").

#### #560 MUST NOT

- Silently truncate a too-old birthday to the operator's horizon.
  Truncation hides which VTXOs are unrecoverable; users must opt
  in explicitly via a `--birthday` re-run.

#### Documentation MUST

- Ship a `docs/wallet-birthday-ux.md` (or equivalent section in the
  existing wallet user guide) that explains the birthday parameter,
  the retention window, the archival horizon, and the failure modes
  in user-facing language. This satisfies #552 acceptance criterion
  3 ("user-facing documentation on the wallet-birthday UX
  tradeoff").

## Open questions / TODO

- **Multi-operator restore** — a wallet that has interacted with
  multiple operators over its lifetime today must restore against
  each operator separately and merge the results. A federated
  announcement protocol (or an off-chain announcement gossip) is
  out of scope for CV-M5 and tracked as
  **[FU-ANN-MULTI-OP]**.
- **Archival sink replication** — single-node deployments using
  `local_path` for archival inherit a single-disk failure domain.
  A replicated archival sink (S3 multi-region, Garage, Ceph) is
  operator-policy today; if it becomes a recovery hazard in
  practice, **[FU-ANN-ARCHIVE-REPLICATE]** captures the work.
- **Compression-ratio empirical validation** — the storage growth
  table assumes uncompressed row sizes. Once #556 lands, a
  follow-up benchmark should measure the actual zstd-compressed
  Parquet size and update operator capacity-planning docs.
  **[FU-ANN-COMPRESSION-BENCH]**.
- **Cold-store query latency budget** — the SLO for archival reads
  is informally "minutes". A formal SLO depends on the operator's
  archival sink choice and is left to the operator-facing runbook
  rather than this ADR.
- **Pruning under operator failover** — if the operator hot-fails
  during a prune cycle (after archive, before delete), a restart
  re-runs the cycle and re-archives the same rows. The archival
  Parquet writes are append-only, so duplicate rows in archival are
  possible. The archival reader (#557) MUST deduplicate on
  `(round_id, vtxo_id)`. Documented here; tracked as
  **[FU-ANN-ARCHIVE-DEDUP]** for explicit test coverage.
- **Birthday-as-time vs. birthday-as-round** — the `birthday`
  parameter is currently a `round_id` string. A wall-clock
  birthday (e.g. "I started using this wallet on 2025-12-01") is
  more user-friendly but requires the operator to expose a
  round-id-by-timestamp index. Out of scope for #560 in the M5
  milestone; a future UX iteration.
- **Auth for derivative endpoints** — `GetRoundAnnouncements` is
  unauthenticated by this ADR's decision, but a future endpoint
  that exposes scan-key-bound data (e.g. a scan-as-a-service
  offering by the operator) would re-introduce the auth question.
  This ADR scopes the decision to the announcement endpoint only.

## References

- Issue #552 (this ADR)
- Issue #523 — `dark-confidential` crate skeleton (dependency)
- Issue #556 — round announcement storage and indexing
- Issue #557 — `GetRoundAnnouncements` gRPC endpoint
- Issue #558 — background stealth scanning loop in `dark-client`
- Issue #560 — wallet restore with stealth VTXO re-scan
- Issue #553 — dual-key meta-address (defines `scan_pk`)
- Issue #554 — sender-side one-time key derivation
- Issue #555 — recipient stealth scanning (consumer of announcements)
- Issue #520 — Go `arkd` E2E parity gate
- ADR-0003 — confidential VTXO memo format (defines `ephemeral_pubkey`
  and the ECDH that announcements feed into)
- `crates/dark-core/src/ports.rs` — `RoundAnnouncement`,
  `RoundRepository::list_round_announcements`
- `crates/dark-live-store/` — host of the announcement table and
  prune job (#556)
- `docs/conventions/repositories.md` — repository-pattern conventions
  this ADR's storage layout follows
