-- Migration 007 (pg): Round announcement storage and indexing (#556).
--
-- Mirrors the SQLite migration 010. See that file for the schema rationale,
-- the index strategy, and the relationship to the pruning policy in #552.
--
-- Idempotent: every CREATE uses IF NOT EXISTS, so re-running this migration
-- against an already-migrated database is a no-op.

CREATE TABLE IF NOT EXISTS round_announcements (
    round_id         TEXT        NOT NULL,
    vtxo_id          TEXT        NOT NULL,
    ephemeral_pubkey TEXT        NOT NULL,
    block_height     BIGINT      NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (round_id, vtxo_id)
);

CREATE INDEX IF NOT EXISTS idx_round_announcements_block_height
    ON round_announcements(block_height);

CREATE INDEX IF NOT EXISTS idx_round_announcements_vtxo_id
    ON round_announcements(vtxo_id);
