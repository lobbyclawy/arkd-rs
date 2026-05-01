# ADR-0008: MuSig2 nonce-injection strategy for VON

- **Status:** Accepted
- **Date:** 2026-04-30
- **Milestone:** VON-M1 (PSAR cryptographic primitives, phase/2)
- **Drives:** #659 → unblocks #660 → #661 → #662 → #663; informs #664, #665
- **Affects:** new `crates/dark-von-musig2`. Existing `crates/dark-bitcoin/src/signing.rs`
  is **untouched** — see "Cross-cutting" §below for the deferred
  migration.

## Context

VON requires that the operator's MuSig2 nonce scalars `(k₁, k₂)` come
from `dark_von::wrapper::nonce` (#655) — i.e., from the deterministic
HMAC-derived `r` plus the ECVRF-bound `R` in ADR-0007 — instead of from
fresh random sampling. The pure-Rust MuSig2 crate already used by
`dark-bitcoin/src/signing.rs:13` is `musig2 = "0.3.1"` (Conduition).
That crate's `SecNonce` constructor is:

```rust
let sec_nonce = SecNonce::build(NonceSeed(seed_bytes))
    .with_seckey(*seckey)
    .with_message(&msg)
    .build();
```

The 32-byte `seed_bytes` flows through internal hashing inside
`SecNonce::build`. The output `(k₁, k₂)` scalars are **not directly
settable from outside** — there is no `SecNonce::from_scalars(k₁, k₂)`
constructor on the public surface. Feeding a deterministic VON output as
`NonceSeed` is incorrect: the seed is hashed away, so VON's binding is
lost.

Three candidate paths from the issue text:

1. **Use `musig2 = 0.3.1` as-is** with VON's `(R₁, R₂)` as the
   `NonceSeed`. Broken — explained above.
2. **Vendor `musig2 = 0.3.1`** into `vendor/musig2-fork/` and add a
   `SecNonce::from_scalars(k₁, k₂)` constructor.
3. **Drop the crate** and implement the BIP-327 routines we need
   directly on `secp256k1 = 0.29`.

This ADR records the choice between (2) and (3) — (1) is non-viable.

## Curve-context survey

Before picking a path, document what's actually in the workspace's
crypto graph today (verified by reading the `Cargo.lock` and listing
the crates' source under `~/.cargo/registry/src/...`):

| Crate | Version | Exposes MuSig2? |
|---|---|---|
| `secp256k1` | 0.29 | **No.** No `musig` module. |
| `secp256k1-zkp` | 0.11 | **No.** `src/zkp/` lists `ecdsa_adaptor`, `generator`, `pedersen`, `rangeproof`, `surjection_proof`, `tag`, `whitelist`. The C lib has `module-musig` but the Rust binding has not wrapped it. |
| `musig2` | 0.3.1 | Yes — pure Rust, the only Rust MuSig2 in the dep graph. |
| `bitcoin` | 0.32 | No (BIP-340 verify only via `secp256k1::verify_schnorr`). |

So "drop the crate and use `secp256k1-zkp`'s MuSig2 surface" is **not
a realistic option** — that surface does not exist. (3) means
implementing BIP-327 ourselves on `secp256k1 = 0.29`.

## Candidates

### Option 1 — Use `musig2 = 0.3.1` as-is (rejected)

The seed flows through internal hashing; no `from_scalars` exists.
Feeding VON output as the seed produces signatures that verify, but
the `(k₁, k₂)` actually used by the crate are not the VON-bound
scalars — they are `H(seed || sk || msg)` etc. VON's binding
(R uniquely determined by `(pk_VON, x)`) is destroyed. Disqualified.

### Option 2 — Vendor `musig2 = 0.3.1` + `from_scalars` patch

Copy `musig2 = 0.3.1` source into `vendor/musig2-fork/`, swap the
workspace dep to `musig2 = { path = "vendor/musig2-fork" }`, add a
`SecNonce::from_scalars(k₁, k₂) -> SecNonce` constructor that
bypasses the `seed → hash → (k₁, k₂)` derivation and stores the
scalars directly. ~50 LOC of patch.

| Pros | Cons |
|---|---|
| Smallest delta (one constructor) | Own a fork forever; upstream fixes/security updates merged manually |
| `dark-bitcoin/src/signing.rs` keeps working without changes | Vendoring 3 KLOC for a 50-LOC patch is asymmetric |
| Wire-compat with upstream `musig2` is automatic | If we upstream the patch and it's accepted, the fork can be retired — but only if Conduition merges |

User explicitly opted out of vendoring as a baseline preference.
Recorded for completeness.

### Option 3 — Hand-roll BIP-327 on `secp256k1 = 0.29` (chosen)

Implement the BIP-327 routines we need as a **private `bip327` module
inside the new `dark-von-musig2` crate**, on top of `secp256k1 = 0.29`.
The surface is bounded — we only need what the VON adapter exercises:

| Routine | Purpose | LOC estimate |
|---|---|---|
| `key_agg_coeff(pubkeys, i)` | KeyAggCoefficient `a_i` per BIP-327 §"Key Aggregation" | ~80 |
| `key_agg(pubkeys) -> AggregatedKey` | Aggregated public key `Q = sum(a_i · X_i)` | ~50 |
| `nonce_coef(agg_nonces, agg_pk, msg)` | `b = H_non(R₁ \|\| R₂ \|\| Q \|\| msg)` per §"Nonce Aggregation" | ~30 |
| `bip340_challenge(R, Q, msg)` | Standard BIP-340 `e = H_BIP340("BIP0340/challenge", R, Q, msg)` | ~30 |
| `partial_sign_with_scalars(sk, k₁, k₂, agg_nonce, agg_pk, msg)` | `s_i = k_{i,1} + b·k_{i,2} + e·a_i·sk_i mod n` | ~80 |
| `aggregate_partial_signatures(parts, R, parity_adj)` | `s = sum(s_i)` + parity flips per §"Signature Aggregation" | ~80 |
| `finalize_bip340(R, s)` | Output 64-byte BIP-340 sig | ~30 |
| Types + errors | `AggregatedKey`, `Bip327Error` | ~120 |

**Total: ~500 LOC**, comparable to ECVRF (#652). Same `#![forbid(unsafe_code)]`
posture, same `EcvrfError`-style typed errors, same constant-time
disposition for secret arithmetic.

| Pros | Cons |
|---|---|
| No fork, no maintenance debt | Real implementation cost (~500 LOC) |
| One curve dep (`secp256k1 = 0.29`) — no new build-time machinery | Audit surface grows by ~500 LOC of crypto we own |
| Direct scalar injection, no `seed → hash` step to bypass | Two MuSig2 implementations coexist (ours + `musig2 = 0.3.1` in `dark-bitcoin`) until the FU below lands |
| Cross-validation with `bitcoin::Secp256k1::verify_schnorr` (#665) gives BIP-340 conformance gate | Cross-validation with `musig2 = 0.3.1` (#660 acceptance) is the wire-compat gate — if our impl drifts from BIP-327 the test trips immediately |

## Decision

**Adopt Option 3.** Implement BIP-327 in a private `bip327` module
inside `crates/dark-von-musig2`, on top of `secp256k1 = 0.29`. The
adapter `sign_partial_with_von(...)` from #660 consumes VON's
`(r₁, r₂)` scalars directly (no `NonceSeed`, no internal hashing),
calls `bip327::partial_sign_with_scalars`, and returns a partial
signature wire-compatible with what `musig2 = 0.3.1` expects on the
participant side.

### `dark-bitcoin` migration: deferred

`dark-bitcoin/src/signing.rs` and `dark-bitcoin/src/tree.rs` keep
their `musig2 = 0.3.1` dependency. The two MuSig2 implementations
coexist for the duration of phase 2 because:

- The participant side of the VON-MuSig2 protocol (#662) reuses
  `dark_bitcoin::signing::generate_nonce` / `aggregate_nonces` as
  the issue text mandates ("The participant side continues to use
  the existing `dark_bitcoin::signing::generate_nonce`").
- Cross-validation between our `bip327` and `musig2 = 0.3.1` happens
  at every #660 acceptance test: a 2-of-2 session where the operator
  uses our handroll and the participant uses `musig2 = 0.3.1`
  produces a signature that **must** verify under
  `musig2::verify_single` (which is itself BIP-340-conformant).
  Any drift in our BIP-327 implementation surfaces immediately.

**Follow-up [FU-MUSIG2-MIGRATE]:** once #663 lands and the handroll
has stabilised across an entire phase-2 horizon, open a tracking
issue to migrate `dark-bitcoin/src/signing.rs` from `musig2 = 0.3.1`
to our `bip327` module (extracting it to a workspace crate
`dark-musig2` if that simplifies the API). Estimate: 2-3 days
including test migration.

## Cross-validation strategy

Three cross-validation gates ensure our BIP-327 stays aligned with
the spec and the rest of the workspace:

1. **`musig2 = 0.3.1` cross-compat (#660 acceptance test)** — operator
   uses handroll, participant uses upstream crate; aggregate verifies
   under `musig2::verify_single`.
2. **BIP-340 verifier (#665 acceptance test)** — every aggregate
   signature in an N=12 horizon verifies under
   `bitcoin::Secp256k1::verify_schnorr`. This is the ground truth
   for BIP-340.
3. **BIP-327 official test vectors (#665 stretch)** — feed
   the operator path with a VON key derived to match upstream
   vector inputs, confirm bit-for-bit equality of the partial
   signature scalars.

The first two are mandatory; the third is informational. Together
they catch ciphersuite drift before #663 merges.

## Consequences

### Positive

- **One curve dep, one curve context.** Same posture as ADR-0001
  and ADR-0006: `secp256k1 = 0.29` everywhere we control.
- **No fork to maintain.** No `vendor/musig2-fork/`, no manual
  upstream merges.
- **Direct scalar injection.** The whole point of VON is that the
  operator commits to `(r₁, r₂)` ahead of time; the handroll
  consumes those scalars as inputs to `partial_sign_with_scalars`,
  no intermediate hashing.
- **Audit surface stays bounded.** ~500 LOC of well-specified BIP-327
  routines, behind `#![forbid(unsafe_code)]`. Smaller than vendoring
  3 KLOC of the upstream crate.

### Negative / follow-ups

- **Two MuSig2 implementations coexist.** Until **[FU-MUSIG2-MIGRATE]**
  lands, both `dark-bitcoin/musig2 = 0.3.1` and our private `bip327`
  module are live in the workspace. Cross-validation gates above
  prevent drift but don't eliminate the duplication.
- **No external audit on the handroll.** Same posture as ADR-0006
  on ECVRF. **Follow-up [FU-MUSIG2-AUDIT]:** book external review of
  `crates/dark-von-musig2/src/bip327/` alongside the
  [FU-VRF-AUDIT] item from ADR-0006, before tagging
  `v0.1-von-psar` (#694).
- **BIP-327 vector situation.** The official BIP-327 test vectors live
  at <https://github.com/bitcoin/bips/blob/master/bip-0327/vectors/>.
  We cannot re-use them verbatim because they pin random nonces; for
  cross-validation we'll feed our derivation with vector-derived
  scalars and check the output partial sigs match. #665 owns this.

### Cross-cutting — constraints on downstream issues

- **#660** MUST register `crates/dark-von-musig2` with
  `secp256k1 = { version = "0.29", features = ["rand"] }` and
  `dark-von = { path = "../dark-von" }` as the only new crypto deps.
  No `musig2 = 0.3.1` dep on this crate. `#![forbid(unsafe_code)]`.
- **#660** MUST organise as: `src/lib.rs`, `src/error.rs`,
  `src/bip327/{mod.rs, key_agg.rs, sign.rs, finalize.rs}` (private),
  `src/sign.rs` (public adapter `sign_partial_with_von`),
  `src/nonces.rs` (public `pub_nonces_from_von`).
- **#660** MUST cross-validate against `musig2 = 0.3.1` via a
  dev-dependency: 2-of-2 session where our handroll on the operator
  side produces a partial sig that, combined with `musig2 = 0.3.1`'s
  participant-side partial, aggregates to a signature accepted by
  `musig2::verify_single`. If this test fails, our BIP-327 has
  drifted; do not merge.
- **#661 / #662 / #663** consume the surface from #660; no new
  BIP-327 routines should appear in those issues.
- **#664** uses `dark_von::wrapper::Proof` (#655) directly — the
  equivocation pair is two valid VON proofs, not two BIP-327 partial
  signatures. Wire size budget ≤ 200 B; per-proof size is 81 B
  (`PROOF_LEN`), so two proofs + small framing fits comfortably.
- **#665** uses `bitcoin::secp256k1::Secp256k1::verify_schnorr` as
  the BIP-340 ground truth. Optional: import a small subset of
  BIP-327 vectors and verify partial-sig equality.

## References

- Issue #659 (this ADR), #660–#665 (downstream).
- BIP-327 — *MuSig2 for BIP-340 compatible Multi-Signatures*:
  <https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki>
- BIP-340 — *Schnorr Signatures for secp256k1*:
  <https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki>
- ADR-0001 — workspace curve-context invariant.
- ADR-0006 — analogous handroll decision for ECVRF.
- ADR-0007 — VON wrapper construction; the operator's `(r₁, r₂)`
  scalars consumed here come from `wrapper::nonce`.
- `crates/dark-bitcoin/src/signing.rs:12-15` — current `musig2 = 0.3.1`
  surface, untouched by this ADR.
- `musig2 = 0.3.1` (Conduition):
  <https://crates.io/crates/musig2/0.3.1>
- `secp256k1-zkp = 0.11` source listing (no `musig` module):
  `~/.cargo/registry/src/index.crates.io-*/secp256k1-zkp-0.11.0/src/zkp/`
