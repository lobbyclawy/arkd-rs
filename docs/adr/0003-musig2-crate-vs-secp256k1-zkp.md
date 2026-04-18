# 0003 — MuSig2 via the `musig2` crate rather than `secp256k1-zkp`

- **Status**: accepted
- **Date**: 2026-04-17 (backfilled)
- **Deciders**: core maintainers

## Context

The Ark protocol uses MuSig2 (BIP-327) to aggregate server + participant
signatures across every node of the VTXO commitment tree during a
round's Finalization phase. Thousands of MuSig2 sessions may run inside
a single round. Two options in the Rust ecosystem:

- [`musig2`](https://crates.io/crates/musig2) — a pure-Rust BIP-327
  implementation that sits on top of `secp256k1` (libsecp256k1).
- [`secp256k1-zkp`](https://crates.io/crates/secp256k1-zkp) — Rust
  bindings to libsecp256k1-zkp, which exposes the upstream MuSig2
  primitives.

Correctness is existential. A subtle off-by-one in nonce handling or
key aggregation locks funds up. Cross-implementation interoperability
with the Go arkd reference must be byte-exact; the Go E2E is the
authoritative check.

## Decision

We use the pure-Rust `musig2` crate. MuSig2 imports are isolated in
`crates/dark-bitcoin/src/musig2/` (the facade established by #496).
Downstream crates (`dark-core`, `dark-signer`) depend on the facade,
not on `musig2::` directly.

## Consequences

- Pure-Rust build; no C toolchain required for MuSig2. This matters for
  aarch64 release builds and for contributor onboarding on Windows.
- One less native dependency in the Docker image.
- We are on the `musig2` crate's API cadence; a breaking change is
  absorbed in one place (the facade) and downstream crates are
  unchanged.
- Performance: within an order of magnitude of libsecp256k1-zkp for
  our workload, which is dominated by per-round session overhead, not
  per-signature hot-path CPU.

## Alternatives considered

- **`secp256k1-zkp`**: lower-level, backed by the upstream C library.
  Lost on toolchain complexity in cross-compile matrices and the
  migration risk at the time of the original decision — it was not yet
  clear whether the Rust binding would stay in sync with upstream
  BIP-327 quickly.
- **A handwritten in-crate MuSig2 implementation**: rejected outright.
  The blast radius of a subtle bug in nonce handling is operator-wide
  fund loss; we do not reinvent this.

A future ADR may revisit this in favour of `secp256k1-zkp` if (1) its
Rust bindings gain upstream parity with BIP-327 revisions faster than
the `musig2` crate, or (2) the facade in `dark-bitcoin::musig2` shows
consistent friction. Today neither is true.
