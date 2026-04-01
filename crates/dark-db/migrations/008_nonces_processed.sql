-- Migration 008: Add nonces_processed column to signing_sessions
-- This flag prevents the race condition where two concurrent SubmitTreeNonces
-- calls both see "all nonces collected" and both try to create ASP partial
-- signatures, consuming single-use MuSig2 SecNonces.
ALTER TABLE signing_sessions ADD COLUMN nonces_processed BOOLEAN NOT NULL DEFAULT FALSE;
