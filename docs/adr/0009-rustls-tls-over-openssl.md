# 0009 — rustls-tls over OpenSSL

- **Status**: accepted
- **Date**: 2026-04-17
- **Deciders**: core maintainers

## Context

dark speaks HTTPS in several places:

- `reqwest` — outbound HTTP to Esplora, to Nostr relays, to CEL
  hot-reload endpoints, etc.
- `sqlx-postgres` — TLS to a managed Postgres.
- `redis` — TLS to a managed Redis.
- `tonic` — gRPC mTLS both inbound (API) and outbound (remote signer).

Each crate can be compiled against OpenSSL (`openssl-sys`) or rustls.
Mixed TLS stacks are compatible at the wire level but blow up at build
time when a cross-compile target cannot find the right OpenSSL.

This concretely broke the release matrix on run `23777043825`
(2026-03-31): `aarch64-unknown-linux-gnu` could not find OpenSSL, and
the fail-fast matrix cancelled the otherwise-green targets.

## Decision

Every TLS-capable dependency is compiled with rustls. Specifically:

- `reqwest`: `default-features = false, features = ["rustls-tls", "json"]`
- `sqlx`: `features = ["runtime-tokio", "tls-rustls", …]`
- `redis`: TLS features via rustls.
- `tonic`: `features = ["tls-ring"]` (or equivalent rustls-backed
  feature in the pinned tonic version).

After the migration, `cargo tree -i openssl-sys` produces no matches
across the workspace. The #508 PR lands the dependency-tree surgery
and adds `fail-fast: false` to the release matrix so a single-target
breakage no longer cancels the others.

## Consequences

- Cross-compile matrix works without installing OpenSSL per target
  container. The release pipeline becomes a pure Rust build.
- One TLS stack to audit, monitor for CVEs, and certify.
- rustls is the Rust ecosystem's default trajectory; choosing it
  aligns with where tooling is going.
- Loss: no PKCS#11 / hardware-HSM integration that relies on
  OpenSSL's engine system. Not a current requirement for dark.
- Ring is an unsafe-Rust crate; we accept that transitive risk and
  track advisories via `cargo audit` and `cargo deny`.

## Alternatives considered

- **Keep OpenSSL and fix the aarch64 cross-container**: works, but
  fragile across distro image updates. Also leaves us with the
  ongoing CVE exposure of the OpenSSL attack surface.
- **Native-tls (platform default)**: inconsistent across Linux / macOS
  / Windows; complicates container builds; not a real candidate.
- **Pin per-crate to whichever TLS stack is easiest**: rejected — the
  whole point is one stack.
