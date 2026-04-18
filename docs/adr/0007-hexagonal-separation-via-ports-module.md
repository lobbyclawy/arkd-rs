# 0007 — Hexagonal separation via a `ports` module

- **Status**: accepted
- **Date**: 2026-04-17
- **Deciders**: core maintainers

## Context

`dark-core` holds the protocol logic — round lifecycle, VTXO tree
construction, MuSig2 cosigning, forfeit handling, sweep. It needs to
call out to storage (`dark-db`, `dark-live-store`), to the Bitcoin
network (`dark-scanner`, `dark-wallet`), to the signer (`dark-signer`),
and to any alerting / Nostr / fee-manager integration.

Without a discipline, those dependencies flow the wrong way: the domain
crate ends up with `use tonic::Status` or `use sqlx::Error` inside its
public surface, and a change in a transport or storage crate ripples
into protocol code. During the pre-parity period some of this layer
bleed accumulated.

## Decision

`dark-core::ports` is the only module inside `dark-core` permitted to
declare traits that concrete infrastructure crates implement. Everything
`dark-core` calls out through is a trait defined here. Downstream
infrastructure crates (`dark-db`, `dark-wallet`, `dark-scanner`, …)
depend on `dark-core`, not the other way around.

Rules:

1. `dark-core` imports no transport-level types (no `tonic::`,
   `sqlx::`, `esplora_client::`). This is enforceable via grep in CI.
2. Every infrastructure-facing trait lives in `dark-core::ports` and
   returns domain error types only.
3. An implementation in a downstream crate provides the concrete
   behaviour; the domain is constructed with trait objects (boot-time
   swap) or with generics where hot-path monomorphisation matters.

## Consequences

- `dark-core` is compilable and testable without pulling in sqlx,
  tonic, or BDK. Unit tests use trivial fakes.
- Per-crate refactors in M1–M3 apply this rule; PR #495 is the
  enforcement step for `dark-core` and #497 applies it to the storage
  layer.
- New integrations (confidential VTXOs, additional indexer endpoints,
  a future HSM signer) plug in at the `ports` seam without touching
  protocol code.
- Cost: traits add indirection and some boilerplate. Worth it — the
  alternative (concrete types threaded through `dark-core`) made large
  refactors impossible without touching protocol logic.

## Alternatives considered

- **No formal separation**: accept that `dark-core` depends on
  concrete crates. This is the state the repo arrived at pre-refactor
  and is what motivated the M1 work.
- **`async-trait` bans in favour of Rust 1.75+ AFIT**: attractive
  technically, but the `dyn`-safe boundary still needs `async-trait`
  or a lot of manual `Pin<Box<dyn Future>>`. Revisit as a workspace-
  wide change (not per-crate) when AFIT's `dyn` story is complete.
- **Moving the ports into a separate `dark-ports` crate**: avoided so
  far because ports and domain types are often siblings in the same
  change. Splitting would force cross-crate coordination for simple
  additions.
