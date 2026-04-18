# 0004 — Signer service isolation

- **Status**: accepted
- **Date**: 2026-04-17 (backfilled)
- **Deciders**: core maintainers

## Context

dark holds the server's long-lived signing key — the key that
co-signs every MuSig2 session in every round, and signs every
commitment and forfeit transaction. Compromise of this key lets an
attacker produce settlements that look authentic to clients. A
production-grade Ark operator typically wants to keep the key material
on a box whose attack surface is smaller than "the full gRPC server
process."

## Decision

Signing is factored behind a `SignerService` trait defined in
`dark-core::ports`. Two implementations:

1. **`LocalSigner`** (`crates/dark-signer`) — runs in-process with
   the key material held in the server's address space. Used when
   isolation is not required (dev, regtest, small mainnet).
2. **`RemoteSignerClient`** (in `dark-signer`) — a thin gRPC client
   that talks to a standalone `dark-signer` binary over mTLS. Key
   material lives only inside that separate process.

The `dark-signer` binary is shipped as a second artifact next to
`dark`. Operators choose at deploy time.

The two implementations satisfy the same trait exactly; drift between
them is a bug — verified by the trait-object test added in #500 and
by the Go E2E (which runs against both configurations in matrix).

## Consequences

- Key isolation is a deployment-time choice, not a compile-time one.
  Operators upgrade to remote signing without recompiling.
- Two binaries to ship, two configs to document. Acceptable — this is
  already the case in the Go arkd reference.
- The `SignerService` trait surface is protocol-critical. Adding a
  method is a coordinated change across three places: trait,
  `LocalSigner`, `RemoteSignerClient`. The test suite catches drift at
  compile time.
- mTLS between server and remote signer is mandatory — plain gRPC is
  explicitly unsupported for remote signing.

## Alternatives considered

- **Always in-process**: simpler deployment, but operators with strong
  custody requirements would have to fork the codebase. Not acceptable
  for the production-readiness posture dark targets.
- **Hardware signer (HSM / Ledger) support as the primary path**:
  deferred. The `SignerService` abstraction is the right seam for this
  to land as a third implementation later; cutting it as the first
  implementation was scope creep at the original decision point.
- **Key sharding / threshold signing**: this is a protocol extension,
  not a custody decision. Out of scope for this ADR.
