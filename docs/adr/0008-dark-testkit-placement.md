# 0008 — Placement of the `dark-testkit` harness

- **Status**: accepted
- **Date**: 2026-04-17
- **Deciders**: core maintainers

## Context

Both test paths — the Rust E2E under `tests/e2e_regtest.rs` and the Go
E2E under `.github/workflows/go-e2e.yml` — need to spawn a dark server
against a regtest Bitcoin node, provide clients, and clean up. Today
each path has its own bespoke setup code. Drift between them means we
are effectively testing two subtly different deployments.

A shared harness is the natural answer, but there is a question of
**where** it lives:

- **Option A**: `tests/support/` under the main crate. Test-only, no
  other crate sees it.
- **Option B**: A new workspace member `crates/dark-testkit` that is
  marked `publish = false`.
- **Option C**: A published crate on crates.io for downstream SDK
  authors to re-use.

## Decision

We will create a workspace member `crates/dark-testkit` (Option B)
with `publish = false`. Other crates' integration tests can depend on
it via `[dev-dependencies]`. The shared `poll_until` helper that ships
in `tests/support/poll.rs` today (introduced by #492) migrates into
`dark-testkit` when #505 lands.

## Consequences

- A single source of truth for regtest orchestration, server spawning,
  and polling helpers.
- Reachable from every crate's integration tests — e.g. `dark-api`
  REST-layer tests in #498, in-process `run()` tests in #500 — without
  copy-paste.
- Not published. External downstream consumers writing their own
  integration tests against dark do not take a dependency on
  `dark-testkit`; they write their own fixture code. This keeps the
  API surface internal and evolvable.
- The `tests/support/` directory under the main crate continues to
  exist only as a transitional home; it is emptied when #505 lands.

## Alternatives considered

- **Option A (`tests/support/`)**: simplest; loses reach — crates
  beyond the main binary cannot share code via `tests/`. Since #498
  and #500 want harness code in their own crates' integration tests,
  this loses.
- **Option C (published crate)**: attractive for SDK authors but
  increases our API-stability commitment. Not worth it until we have a
  clear downstream consumer requesting it, and that consumer is
  better served by a separate, minimal client-test helpers crate.
- **A `dev-dependencies`-only shared `tests/` symlink**: rejected for
  platform-portability reasons.
