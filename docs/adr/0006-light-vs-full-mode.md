# 0006 — Light vs full deployment mode

- **Status**: accepted
- **Date**: 2026-04-17 (backfilled)
- **Deciders**: core maintainers

## Context

dark needs to serve two very different operator profiles:

- **Light**: a solo operator on a VPS or home server running testnet
  or a small-scale mainnet service. No Postgres, no Redis, no separate
  signer box. The bar is "runs on one machine, `docker compose up`."
- **Full**: a production operator running at scale with hot-standby
  requirements. Postgres for durable storage, Redis for shared live
  state across replicas, remote signer for key isolation, Prometheus
  scraping for observability.

The naive choice is to build two separate binaries or two compile-time
feature flags. Both have historically been a maintenance tax: flags
multiply the build matrix, and separate binaries diverge on
protocol-adjacent code paths.

## Consequences — existing state

The workspace has a `light` cargo feature today. Mode is *also*
selected at config time via `deployment.mode = "light" | "full"`.
These two selection mechanisms coexist and have overlapping scope.

## Decision

Light vs full is a **runtime config switch**, not a cargo feature.
One binary; the configured `deployment.mode` controls:

- Database URL pattern → SQLite or Postgres (dispatch inside
  `dark-db` at the trait implementation level).
- Live store backend → `InMemoryStore` or `RedisStore` (dispatch inside
  `dark-live-store`).
- Default ports, log format, metrics endpoint defaults.

The existing `light` cargo feature is kept as an *infrastructure
convenience* for Docker builds (e.g. omitting the Postgres client from
the light image), not as a behavioural gate. No business logic lives
behind `#[cfg(feature = "light")]`.

A design-decision issue (see the `#493` / `#510` follow-ups list) may
revisit whether the cargo feature carries its weight or should be
removed entirely once #503/#504 land.

## Consequences

- Operators pick their mode by editing config; no rebuild required.
- The two dispatch points are `dark-db` and `dark-live-store` — clean,
  bounded surfaces. The rest of the code is mode-agnostic.
- Docker image size asymmetry: the light image can skip Postgres and
  Redis client libraries (runtime), but since the binary is built
  with both, it's the same binary in both images. This is an
  acceptable trade — operators running light images still get the
  option to switch to full without re-downloading.
- Documentation burden: `docs/light-mode.md` exists; `docs/runbook.md`
  must cover both modes. #511 owns that refresh.

## Alternatives considered

- **Separate binaries (`dark-light`, `dark-full`)**: high divergence
  risk; every RPC handler would need coverage in both matrices.
- **Cargo-feature-gated business logic**: rejected — the feature
  matrix proliferates fast and the E2E suite can't feasibly cover
  every flag combination.
- **A third "medium" mode**: explicit non-goal. Two modes are already
  a significant documentation surface; a third would dilute attention.
