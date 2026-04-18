# 0001 — sqlx over diesel

- **Status**: accepted
- **Date**: 2026-04-17 (backfilled; original decision predates the repo's
  current main)
- **Deciders**: core maintainers

## Context

dark needs to persist rounds, VTXOs, intents, forfeit transactions, bans,
and related indexed state. The workspace already runs `tokio` as its
async runtime (tonic, redis, reqwest all async). We also want the same
persistence code to target SQLite (light-mode deployments) and
PostgreSQL (production). The two most widely used Rust options are
`sqlx` and `diesel`.

Operational constraints:

- SQL visibility matters. Reviewers reading a handler need to see the
  query, not reconstruct it from a DSL. This codebase has had at least
  one protocol-critical bug hidden by query opacity.
- Runtime is tokio. Blocking queries wrapped in `spawn_blocking` would
  add scheduler pressure and obscure cancellation.
- Both SQLite and PostgreSQL must share the same repository trait
  surface and, ideally, the same migrations.
- Compile-time query validation is nice-to-have, not blocking. The
  cost of `sqlx::query!` running against an offline-prepared cache
  is acceptable.

## Decision

We use [`sqlx`](https://github.com/launchbadge/sqlx) for persistence.
Repository traits live in `dark-db::traits`; SQLite and PostgreSQL
adapters live in `dark-db::sqlite` and `dark-db::postgres`. Migrations
are a single shared `.sql` set that targets both backends
(see #497 for the migration equivalence work).

## Consequences

- Handwritten SQL everywhere. Reviewers can read the query in place;
  the cost is that a mistyped column surfaces at runtime (or at compile
  time with `sqlx::query!`, which requires a `DATABASE_URL` during build
  or an offline-prepared cache).
- Async-native. Every repository method is `async fn` without
  `spawn_blocking`.
- SQLite and PostgreSQL share most query strings. Divergences are rare
  enough to inline per-backend where they occur, not abstract across a
  DSL.
- No compile-time row-type validation for queries built dynamically.
  That's a deliberate trade — dynamic queries in diesel pay a heavy
  ergonomics tax.

## Alternatives considered

- **diesel**: query-builder DSL with compile-time type checking. Lost
  on (1) readability in PRs — reviewers see `.filter(…).select(…)`
  instead of SQL, (2) async ergonomics — `diesel-async` exists but is
  less mature, (3) harder to target two backends with shared queries.
- **sea-orm**: ORM-style with async support. Lost on the same
  readability concern as diesel, plus it adds a larger surface area
  than we need.
- **rusqlite + tokio-postgres directly**: full control, no abstraction.
  Lost because every crate would reimplement the same connection-pool,
  migration, and retry code.
