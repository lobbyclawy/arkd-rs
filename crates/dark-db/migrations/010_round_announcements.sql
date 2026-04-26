-- Migration 010: Round announcement storage and indexing (issue #556)
--
-- Persists per-round stealth-VTXO announcement tuples
-- (round_id, vtxo_id, ephemeral_pubkey) so scanning clients can fetch them
-- without downloading full VTXO data. Retention follows the policy decided in
-- issue #552 (m5-dd-pruning) — this migration only provides the schema and
-- the indexes the pruning job requires.
--
-- Schema choices:
--   - `(round_id, vtxo_id)` as the composite PRIMARY KEY makes inserts
--     idempotent at the DB layer (re-emitting a round commit does not produce
--     duplicate rows). It also gives us the stable ordering scanning clients
--     paginate over.
--   - `block_height` is recorded on insert so the pruning job can drop
--     announcements below a cutoff in O(log N) via the index below. It also
--     lets clients resume sync from a block height after a long offline
--     period.
--   - `created_at` is a wall-clock fallback for diagnostics / metrics — not
--     used for ordering or pruning.
--   - `ephemeral_pubkey` is stored as TEXT (hex-encoded compressed pubkey)
--     to match the API surface in `RoundAnnouncement` and to avoid a BLOB
--     conversion at every read.
--
-- Indexes:
--   - PK on `(round_id, vtxo_id)` covers `list_for_round` and the
--     paginated `(round_id, vtxo_id)` cursor used by the gRPC stream.
--   - `idx_round_announcements_block_height` covers `list_after_height` and
--     `prune_before` — both are range scans on `block_height`.
--   - `idx_round_announcements_vtxo_id` covers reverse lookups
--     ("which round announced this VTXO?") used by client-side rescans.
--
-- Idempotent: every CREATE uses IF NOT EXISTS, so re-running this migration
-- against an already-migrated database is a no-op.
CREATE TABLE IF NOT EXISTS round_announcements (
    round_id         TEXT    NOT NULL,
    vtxo_id          TEXT    NOT NULL,
    ephemeral_pubkey TEXT    NOT NULL,
    block_height     INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY (round_id, vtxo_id)
);

CREATE INDEX IF NOT EXISTS idx_round_announcements_block_height
    ON round_announcements(block_height);

CREATE INDEX IF NOT EXISTS idx_round_announcements_vtxo_id
    ON round_announcements(vtxo_id);
