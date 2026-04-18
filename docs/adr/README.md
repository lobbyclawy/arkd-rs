# Architecture Decision Records (ADRs)

This directory holds dated, one-page decision records for the non-obvious
choices in dark. Each ADR answers the question: "why this, not the
alternatives?" in a form that is durable and linkable.

An ADR is not an API reference. It does not replace rustdoc. It records a
decision, the context that produced it, and the consequences the codebase
now lives with. When a decision is superseded, the old ADR stays in place
with its status flipped to `superseded` and a link to the replacement.

## Index

| #   | Title                                                                                         | Status    |
| --- | --------------------------------------------------------------------------------------------- | --------- |
| 1   | [sqlx over diesel](0001-sqlx-over-diesel.md)                                                  | accepted  |
| 2   | [tonic 0.12 pin](0002-tonic-0.12-pin.md)                                                      | accepted  |
| 3   | [MuSig2 via the `musig2` crate rather than `secp256k1-zkp`](0003-musig2-crate-vs-secp256k1-zkp.md) | accepted  |
| 4   | [Signer service isolation](0004-signer-service-isolation.md)                                  | accepted  |
| 5   | [CEL fee programs](0005-cel-fee-programs.md)                                                  | accepted  |
| 6   | [Light vs full deployment mode](0006-light-vs-full-mode.md)                                   | accepted  |
| 7   | [Hexagonal separation via a `ports` module](0007-hexagonal-separation-via-ports-module.md)    | accepted  |
| 8   | [Placement of the `dark-testkit` harness](0008-dark-testkit-placement.md)                     | accepted  |
| 9   | [rustls-tls over OpenSSL](0009-rustls-tls-over-openssl.md)                                    | accepted  |

## Template

Copy [`TEMPLATE.md`](TEMPLATE.md) when adding a new ADR. Keep it under two
pages. Link the ADR from the source files that embody the decision
(rustdoc, a top-of-file comment) so a reader moving code-first finds the
decision record.

## Status values

- `proposed` — open for discussion; not yet applied to the code.
- `accepted` — decision made; code conforms.
- `superseded` — replaced by a newer ADR (link the successor in the
  status line).
- `deprecated` — no longer the current choice but not yet superseded; a
  follow-up ADR is expected.
