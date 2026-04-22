# Compliance source-of-funds proofs

`dark-core` now includes an incremental source-of-funds proof module behind the `compliance-proofs` feature flag.

## What it proves

A prover can show that a subject VTXO descends from an ancestor VTXO by revealing only the shared public commitment path plus an owner Schnorr signature.

The proof does **not** reveal:

- VTXO amounts
- Asset quantities
- Any wallet-local metadata

## Current limits

- Proofs are bounded by `max_depth`.
- Verification requires the verifier to know the public commitment txids for the relevant rounds.
- This is a commitment-path proof, not the full nullifier graph disclosure planned for issue #567.

## Verification rules

A verifier accepts a proof only if:

1. The ancestor path is a prefix of the subject path.
2. Every disclosed commitment exists in the verifier's public commitment index.
3. The owner signature matches the canonical proof payload.

## Intended follow-up

This module is scaffolding for the full selective-disclosure flow:

- attach explicit nullifier-to-VTXO edges
- expose client/server transport types
- add CLI and gRPC verification surfaces
