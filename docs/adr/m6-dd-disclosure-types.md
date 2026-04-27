# ADR-M6-DD: Disclosure proof types shipping at launch

- **Status:** Proposed
- **Date:** 2026-04-25
- **Milestone:** CV-M6 (Selective Disclosure & Compliance)
- **Drives:** #563 → constrains #565, #566, #567, #568, #569 → informs #570
- **Affects:** `dark-confidential::disclosure` module surface, the wire
  layout of compliance bundles defined by #562, the `ark-cli disclose`
  command surface (#568), and the `VerifyComplianceProof` gRPC endpoint
  (#569). No on-chain/protocol-rule changes; transparent paths
  untouched (#520 parity gate).
- **Companion ADRs:** ADR-0001 (secp256k1-zkp integration — pins the
  curve and the range-proof construction the v1 bounded-range type
  inherits if it ships); ADR-0002 (nullifier derivation — pins the
  graph-link primitive the source-of-funds proof inherits if it ships);
  ADR-M5-DD-stealth-derivation (defines `MetaAddress`, `scan_pk`,
  `spend_pk`, the issuer-signature key material that signs every
  bundle); the companion *bundle-format* ADR (#562, scheduled in
  parallel with this one) defines the outer envelope; this ADR
  populates the `proof_type` enum it carries.

## Context

A compliance proof in Ark's confidential layer is a **standalone, third-
party-verifiable artefact** that a user voluntarily emits to attest
something about their VTXOs without surrendering spending authority and
without exposing the operator to a custody/disclosure obligation. The
threat model that makes such proofs interesting is two-sided:

- The **operator** sees commitments, nullifiers, and the linkable
  graph (per ADR-0002, ADR-0004 and the confidential round-tree work
  in CV-M2/M3). It does NOT see amounts or the binding between
  on-chain VTXO ownership and an off-chain real-world identity. A
  compliance proof intentionally leaks a **bounded** amount of
  information *to a chosen verifier* — not to the operator and not to
  the public — so that the user can satisfy an institutional
  counterparty (auditor, exchange's deposit-screening team, regulator
  performing a Travel Rule check) while keeping the rest of their
  graph private.
- The **verifier** is an arbitrary third party. They have a copy of
  the bundle (handed to them by the user, or fetched from
  `VerifyComplianceProof` / #569), public on-chain data (round
  commitments, the nullifier set), and the user's signing pubkey.
  They MUST be able to verify the proof with no operator interaction
  beyond reading public state. Verification MUST run in seconds on a
  laptop, MUST NOT require the verifier to re-trust any
  cryptographic primitive that is not already audited in the
  workspace, and MUST produce a binary accept/reject answer plus a
  small set of structured fields (e.g. the disclosed VTXO id, the
  range bound, the source round id) that the verifier renders to a
  human auditor.

Issue #563 asks one decision question: *which proof types ship at
launch and which are deferred?* The roadmap (#561, #562, #564, #565,
#566, #567, #568, #569) names four candidates — viewing keys, VTXO
selective reveal, bounded-range proofs, source-of-funds proofs — and
flags the latter two as "more cryptographically complex". This ADR
makes the launch-scope decision **precisely**, so each downstream
implementation issue knows exactly what wire-tag to emit, what
verifier algorithm to invoke, and which corners are deferred behind a
feature flag rather than partially-implemented in `main`.

A *curated* set is preferable to a *free-for-all* enum for four
concrete reasons:

1. **Verifier complexity grows superlinearly with proof variety.**
   Each new `proof_type` enum case is a new audited verifier path:
   parser, decoder, transcript-binding check, primitive verifier
   call, structured-result mapper. A v1 with two types is two
   audited paths; v1 with five types is five paths plus
   N·(N-1)/2 *interactions* (a verifier must reject a bundle that
   claims to be type A but whose payload bytes carry type-B
   internals). We cap v1 at the smallest set that covers the
   primary institutional use cases identified in #570 and defer
   the rest.

2. **Audit-tool compatibility lives in the wire-tag namespace.**
   Third-party auditors will write small Rust/Python clients that
   pattern-match on the `proof_type` field. If we ship a permissive
   enum and let it widen post-launch, those tools either stop
   handling new types (silent under-audit) or crash on unknown
   types (DoS surface for a malicious user who ships a "future"
   type to confuse a verifier). The bundle-format ADR (#562)
   resolves the *unknown-tag* policy; this ADR fixes the **known**
   tag set so auditors can cache a complete handler map.

3. **Cryptographic-construction churn cannot ship to mainnet.**
   The bounded-range proof (#566) and source-of-funds proof
   (#567) name primitives that are either not audited in the
   workspace today (Bulletproofs — see ADR-0001's FU-BP, which
   re-scoped #525 from Bulletproofs to Back-Maxwell rangeproofs)
   or are graph-walk constructions whose negative-test surface is
   wide. Shipping them under a feature flag and exercising them in
   regtest before they appear in mainnet bundles is the only way
   to keep `cargo audit` clean and the `dark-confidential` crate's
   public surface stable.

4. **Each named type pins a verifier algorithm.** We cannot ship a
   `proof_type = BoundedRange` whose verifier is "consult ADR
   later". This ADR pins the algorithm — by crate path and method
   name — for every type that ships at launch, so the verifier
   binary is determined-by-construction the moment a bundle is
   emitted. Future versions of a type can add fields under
   additive forward-compat rules (see "Backwards compat") but
   cannot swap algorithms without a new wire-tag.

The output of this ADR is a closed v1 set of proof types, one verifier
per type, a deferred set with rationale and follow-up tracking tags,
and a forward-compat rule that a v2 type can be added without breaking
v1 verifiers.

## Requirements

- **Closed v1 set.** The shipped proof-type enum is a finite list of
  named cases. Verifier code paths exist for every case, are
  exercised by unit + property tests, and are covered by negative
  tests. Cases listed as "deferred" in this ADR MUST NOT appear in a
  mainnet bundle until a follow-up issue lands a verifier and a
  v2 ADR amends the set.
- **One algorithm per name.** Each shipping case names a single
  verifier algorithm (crate path + function name + version). A
  future swap (e.g. Bulletproofs replaces Back-Maxwell for a
  bounded-range proof) requires minting a new wire-tag and a new
  case, NOT re-pointing the existing tag.
- **Verifier reachable from the workspace as it stands at the
  CV-M6 ship gate.** No deferred audit, no `git clone` outside
  the workspace, no language-port that has not been smoke-tested.
  Each named verifier function MUST be either already merged in
  `main` (bullet of evidence: file path + line) or part of the
  CV-M6 implementation issue chain that gates the ship.
- **Bundle-tag stability.** Wire-tag bytes are forever. Reusing a
  tag for a different algorithm — even after a major-version bump
  — is forbidden; v2 mints a new tag.
- **Forward-compat rejection.** A verifier MUST reject any bundle
  whose `proof_type` is outside its known set with a structured
  `ProofVerifyError::UnknownProofType { tag }` that surfaces the
  numeric tag. Silently ignoring unknown types is forbidden
  (issue #562 acceptance criterion 3 makes this explicit; this
  ADR pins the corresponding case).
- **Issuer signature is mandatory.** Every bundle carries a
  signature over the canonical-encoded payload, verifiable
  against an issuer pubkey published or pinned out-of-band. The
  signing scheme is BIP-340 Schnorr over secp256k1 (parity with
  `dark-confidential::balance_proof`'s tagged-hash style and
  ADR-M5-DD's `spend_pk`). This ADR does NOT introduce a new
  signature scheme.
- **No new curve, no new hash family.** All v1 verifiers run on
  secp256k1, SHA-256, and HMAC-SHA-256. ADR-0001 pins
  `secp256k1 = 0.29` and `secp256k1-zkp = 0.11`; this ADR does
  not relax that pin.
- **No interactive proofs at launch.** Every v1 type is
  non-interactive. The user emits the bundle once; the verifier
  consumes it offline. Interactive zero-knowledge protocols
  (e.g. multi-round Sigma proofs) are out of scope until a future
  ADR.
- **Composable inside one bundle.** A user emitting more than one
  proof for the same VTXO (e.g. a viewing key for round range
  100..200 *and* a selective reveal of one specific VTXO inside
  that range) MUST be able to ship them as **independent
  bundles** in v1. Multi-proof composition into one envelope is
  deferred (see "Deferred").

## Candidate proof types

The candidate space, ordered by "how much information the proof
discloses to the verifier" from least to most:

### A. `ViewingKeyIssuance` — scoped read-only credential

**What it proves.** The bundle carries a viewing key (a derived
scalar that lets the verifier ECDH-decrypt the user's memos for
VTXOs inside a declared scope; see ADR `m6-dd-viewing-scope`
landing in parallel under #561). The "proof" is the issuance
itself — the verifier does not run a zero-knowledge check; they
walk the user's memos with the key and read amounts directly.
This is the strongest disclosure (the verifier sees per-VTXO
amounts inside the scope) and the simplest cryptography: no
zero-knowledge, just authenticated decryption.

**Verifier algorithm sketch.** Given
`(viewing_key, scope, issuer_pk)` from the bundle and the issuer's
Schnorr signature over the bundle payload:

1. Verify the issuer signature over the canonical-encoded bundle
   body. Reject on bad sig.
2. Walk every memo announced in the scope window (per ADR-M5-DD-
   announcement-pruning, scope is bounded by `round_id_start ..
   round_id_end_exclusive`). For each memo, attempt
   `decrypt_vtxo(viewing_key, memo) -> Option<(amount, blinding)>`.
   In-scope memos that decrypt yield a `(vtxo_id, amount,
   blinding)` triple that the verifier renders.
3. Out-of-scope memos return `None` (per #564 acceptance
   criterion). The verifier MUST NOT treat `None` as failure —
   only as "not relevant to this key".

The verifier's report is a list of `(vtxo_id, amount, blinding)`
plus the scope bounds the issuer signed.

### B. `VtxoReveal` — Pedersen commitment opening (#565)

**What it proves.** The user shares the opening
`(amount, blinding)` of a single committed VTXO. Any third party
verifies `commit(amount, blinding) == stored_commitment` from
public on-chain data. Reveals the amount of *exactly one* VTXO;
reveals **nothing** about siblings, descendants, or the broader
graph (the issue text makes this explicit).

**Verifier algorithm sketch.** Given
`(vtxo_id, amount, blinding, issuer_signature)` and the
publicly-readable `stored_commitment` for `vtxo_id`:

1. Verify the issuer signature over `(vtxo_id, amount, blinding,
   bundle_metadata)`. Reject on bad sig.
2. Look up `stored_commitment` from public round data (the
   verifier pulls it from `GetRoundCommitments` / equivalent
   read endpoint, or an out-of-band dump from the operator's
   public state).
3. Recompute `expected = PedersenCommitment::commit(amount,
   blinding)`.
4. Constant-time-compare `expected.to_bytes() ==
   stored_commitment.to_bytes()`. Accept iff equal.

The verifier's report is `{vtxo_id, amount, accepted}` plus the
Pedersen-commitment-equality witness.

### C. `BoundedRange` — `committed_amount < threshold` without revealing amount (#566)

**What it proves.** The user proves the committed VTXO amount
satisfies a public bound (`amount ∈ [0, max)`, or
`amount ∈ [min, max]`) without revealing `amount` itself.
Canonical institutional use case: "this VTXO is under a Travel
Rule threshold" without disclosing the actual figure. The
construction is a tightened range proof: the existing
`dark-confidential::range_proof::prove_range` proves `amount ∈
[0, 2^64)`; #566 adds prove/verify variants that bind the
witness range to caller-supplied bounds.

**Verifier algorithm sketch.** Given
`(commitment, max, proof, issuer_signature)`:

1. Verify the issuer signature over the bundle body. Reject on
   bad sig.
2. Verify the underlying range proof binds `commitment` to a
   verified inclusive range
   `[lo, hi] = verify_range_bounded(&commitment, &proof)?`.
3. Assert `hi <= max`. (For a two-sided variant: also assert
   `lo >= min`.) Reject if either bound fails.
4. Note: the underlying `verify_range_bounded` returns the
   *natural* range from Back-Maxwell's `exp/min_bits` auto-
   sizing, which can be wider than the prover intended (per
   `crates/dark-confidential/src/range_proof.rs`'s comment).
   The bundle MUST carry the prover's intended `(min_bits, exp)`
   parameters so the verifier reconstructs the exact range the
   prover meant; otherwise a prover who picked a generous
   bit-width could collide with the bundle's claimed `max`.

The verifier's report is `{commitment, max, accepted}` plus
optionally `{verified_range: [lo, hi]}` for diagnostics.

### D. `SourceOfFunds` — graph-traceability proof over linkable nullifiers (#567)

**What it proves.** The user proves "this VTXO traces back N
hops to a specific source VTXO" by walking the *linkable graph*
(nullifier → vtxo → nullifier → ...) — a side-effect of the
nullifier scheme being linkable per ADR-0002. The proof reveals
the graph shape but **not** the amounts at each hop. Canonical
use: AML provenance (this VTXO descends from a deposit at a
licensed on-ramp).

**Verifier algorithm sketch.** Given
`(target_vtxo_id, ancestor_vtxo_id, chain: Vec<HopLink>,
issuer_signature)` where each `HopLink = (nullifier_at_n,
spent_vtxo_id_at_n, output_vtxo_id_at_n_plus_1,
round_commitment_proof)`:

1. Verify the issuer signature over the chain-encoded bundle
   body. Reject on bad sig.
2. For each link `(n_i, v_i, v_{i+1}, π_i)`:
   a. Re-derive `nullifier(v_i)` from the user's secret-key
      witness embedded in the link (the issuer signs the
      derivation; the verifier does not need the secret key
      itself, only the public attestation that the user
      controlled `v_i` when minting `n_i`).
   b. Check that `n_i` appears in the public nullifier set at
      the round in which `v_{i+1}` was minted (i.e. `v_{i+1}`'s
      round consumed `n_i`). The proof carries the Merkle
      inclusion path for `v_{i+1}` against its round commitment.
   c. Check that `v_{i+1}` is on-chain via the round commitment.
3. The chain MUST be of length `≤ max_depth` (bundle field) to
   bound verifier work and per the issue's "documented limits"
   acceptance criterion.
4. Accept iff every link verifies AND `chain[0].spent_vtxo ==
   ancestor_vtxo_id` AND `chain[N-1].output_vtxo ==
   target_vtxo_id`.

The verifier's report is `{target, ancestor, hops, accepted}`.
Amounts at intermediate hops are NOT in the report (the bundle
does not carry openings).

### E. `AggregateBalanceThreshold` — sum of multiple commitments crosses a threshold (post-launch candidate)

**What it proves.** Given a set of commitments `{C_1, ..., C_k}`
the user controls, prove that `Σ amount_i ≥ threshold` (a
"proof of reserves" lower bound) without revealing individual
amounts. The natural construction is a homomorphic sum
`C_sum = Σ C_i = (Σ amount_i)·G + (Σ blinding_i)·H` plus a
range proof on `C_sum - threshold·G` showing it sits in
`[0, 2^64)`.

**Status.** Considered for v1 but **not** shipped — see
"Decision". The cryptographic primitives needed are the same
ones the v1 set uses (Pedersen + Back-Maxwell range proof), but
the bundle layout and the API surface (which set of VTXOs the
user is asserting control over) are not pinned by any current
issue and would require a new ADR.

### F. `SetMembershipNotInSanctioned` — proof a committed input is NOT in a public sanctioned-input set (post-launch candidate)

**What it proves.** Given a public list of sanctioned VTXO ids
(or sanctioned addresses, mapped to deposit VTXOs), prove that
a target VTXO does NOT appear in that set. Canonical use case:
exchange deposit screening that wants a positive "this deposit
is clean" proof rather than the source-of-funds chain.

**Status.** Out of scope for v1 — see "Decision". Negative
set-membership proofs at scale (10k+ entry sets) require either
a Merkle-style accumulator commitment to the sanctioned list
(deferring trust to whoever signs the list snapshot) or a fancy
zk primitive (Caulk, Curve Trees) that the workspace does not
ship today. The set-of-sanctioned-inputs concept also has
governance externalities (whose list?) that a cryptography ADR
should not legislate.

### G. `MultiProofEnvelope` — composition of multiple sub-proofs in one bundle (post-launch candidate)

**What it proves.** Lets a user ship "viewing key for scope X
AND selective reveal for VTXO V AND bounded-range proof for
VTXO V" inside one envelope, with one issuer signature over
the bundle. Reduces wire size and gives the verifier a single
acceptance gate.

**Status.** Out of scope for v1 — see "Decision". The envelope
format defined by #562 is a *single*-proof envelope; widening
it to a heterogeneous list complicates the unknown-tag rejection
policy and the issuer-signature transcript binding. v1 ships
multiple bundles when a user needs multiple disclosures.

## Decision

**Adopt a closed v1 set of three proof types**, with two more
deferred behind feature flags inside the same crate. Ship plus
deferred-but-on-the-roadmap layout:

| Wire-tag (u16, BE) | Name                  | Status   | Verifier algorithm |
|--------------------|-----------------------|----------|--------------------|
| `0x0001`           | `ViewingKeyIssuance`  | **Ship** | `dark-confidential::disclosure::viewing_key::verify_viewing_key_issuance` |
| `0x0002`           | `VtxoReveal`          | **Ship** | `dark-confidential::disclosure::vtxo_reveal::verify_vtxo_reveal` |
| `0x0003`           | `BoundedRange`        | **Ship** | `dark-confidential::disclosure::bounded_range::verify_amount_bounded` (gated `#[cfg(feature = "bounded-range-proof")]`; default-on at the CV-M6 ship gate) |
| `0x0004`           | `SourceOfFunds`       | Deferred | (gated `#[cfg(feature = "source-of-funds-proof")]`; default-off at CV-M6 ship gate; flips to default-on once #567 verifier and end-to-end tests merge) |
| `0x0005`           | `AggregateBalanceThreshold` | Deferred | not implemented; reserved tag |
| `0x0006`           | `SetMembershipNotInSanctioned` | Deferred | not implemented; reserved tag |
| `0x0007`           | `MultiProofEnvelope`  | Deferred | not implemented; reserved tag |
| `0x0000`           | (reserved — invalid)  | —        | parsers reject `0x0000` to keep "all-zero bundle" failures noisy |

The shipping set covers **the four primary institutional use
cases** identified in the issue text and #570:

- *Auditor read-access to a fixed scope* — `ViewingKeyIssuance`.
- *Per-tx selective disclosure* — `VtxoReveal`.
- *Travel Rule threshold attestation* — `BoundedRange`.
- *AML provenance to a known-clean source* — `SourceOfFunds`,
  shipped behind a feature flag that the CV-M6 release manager
  flips once #567 lands the implementation and verifier (the
  issue is large/complex enough that we keep the wire-tag
  reserved from day one but do NOT block CV-M6 on the proof
  itself shipping in mainnet bundles).

Note on ordering relative to the issue text: the issue's "MVP
recommendation" was *(viewing keys, VTXO reveal)* and *(bounded-
range, source-of-funds)* as stretch. We ship `BoundedRange` as
**MVP** (not stretch) for two reasons:

- The Travel Rule use case is the most commonly cited
  institutional driver in the milestone framing (#570). Shipping
  CV-M6 without it leaves early integrators without a way to
  attest "below threshold" except by full reveal — a privacy
  regression that institutional users were promised they would
  not face.
- The verifier already exists in the workspace today.
  `dark-confidential::range_proof::verify_range_bounded`
  (`crates/dark-confidential/src/range_proof.rs`) returns an
  inclusive verified range; #566 wraps it with a public-bound
  comparison. The audit surface added is the `<= max` /
  `>= min` integer check, not a new ZK construction.

We ship `SourceOfFunds` **deferred but with a reserved tag**
because (a) the verifier is non-trivial (graph-walk + per-link
Merkle inclusion + signature transcript), (b) the negative-test
surface is wide (forged hops, cycle attacks, replay across
chains), and (c) institutional users have a fallback —
`ViewingKeyIssuance` for the relevant scope reveals the same
information at a courser granularity.

Why three (not two, not five)? Two is too few to cover the
Travel Rule case without a privacy regression; five forces
`AggregateBalanceThreshold` and `SetMembershipNotInSanctioned`
into the v1 audit surface before either has a pinned wire layout
or a workspace-resident verifier. Three is the smallest set that
covers the primary use cases without shipping audit-incomplete
constructions.

Why a u16 wire-tag and not a u8? `u8` saves a byte but caps the
reserved space at 256. The bundle envelope (#562) is CBOR-based
in the candidate format ADR; CBOR's variable-length integer
encoding makes the byte savings of u8 vs u16 zero in practice
for small tag values, while the headroom for future types is
65k vs 256. We pick u16 BE for parity with the announcement-
table cursor encoding (ADR-M5-DD-announcement-pruning's
`(round_id, vtxo_id)` tuple) and the gRPC schema's general
preference for explicit integer widths.

## Verifier-algorithm pinning

Each shipping type names exactly one verifier function. The
pinning is by **crate path + function name + ADR version**.
Future swaps require minting a new wire-tag (see "Backwards
compat").

### `ViewingKeyIssuance` (wire-tag `0x0001`)

- **Crate path:** `dark-confidential::disclosure::viewing_key`
- **Function:** `pub fn verify_viewing_key_issuance(bundle:
  &ViewingKeyBundle, issuer_pk: &PublicKey, scope_state:
  &ScopeReadState) -> Result<ViewingKeyVerification>`
- **Construction:** Schnorr-signature verification (BIP-340 over
  secp256k1, tagged hash `dark-confidential/disclosure/viewing-
  key-issuance/v1`) over the canonical-encoded bundle body, plus
  a per-memo authenticated-decryption walk reusing the
  ChaCha20-Poly1305 + HKDF construction from ADR-0003. The
  scoping primitive (which key derives what scope) is owned by
  ADR `m6-dd-viewing-scope` (#561, scheduled to land in parallel
  with this ADR).
- **Crate-resident dependency surface:** `secp256k1 = 0.29`
  (signature verify), `chacha20poly1305 = 0.10` (memo decrypt
  per ADR-0003).
- **Implementation issue:** #564 (`issue_viewing_key`,
  `decrypt_vtxo`).
- **Audit notes:** the verifier walks public memos; secret-data
  timing side-channels are confined to the issuer (who supplied
  the viewing key). The verifier holds the viewing key as
  *public* material relative to its own threat model — once a
  verifier has the bundle, the viewing key in it is
  decryption-equivalent to the auditor's authority anyway.

### `VtxoReveal` (wire-tag `0x0002`)

- **Crate path:** `dark-confidential::disclosure::vtxo_reveal`
- **Function:** `pub fn verify_vtxo_reveal(bundle:
  &VtxoRevealBundle, issuer_pk: &PublicKey, public_state:
  &PublicCommitmentState) -> Result<VtxoRevealVerification>`
- **Construction:**
  1. Schnorr verify (BIP-340, tag
     `dark-confidential/disclosure/vtxo-reveal/v1`) over
     `(vtxo_id_bytes || amount_be8 || blinding_be32 ||
     bundle_metadata_bytes)`.
  2. `expected = PedersenCommitment::commit(amount, &blinding)`
     (the existing `crates/dark-confidential/src/commitment.rs`
     constructor).
  3. Constant-time byte equality:
     `subtle::ConstantTimeEq::ct_eq(expected.to_bytes(),
     public_state.commitment(vtxo_id)?.to_bytes())`.
- **Crate-resident dependency surface:** `secp256k1 = 0.29`,
  `subtle = 2.5` (workspace pin via `dark-confidential`).
- **Implementation issue:** #565
  (`reveal_vtxo` / `verify_vtxo_reveal`).
- **Audit notes:** the verifier's only secret-shaped input is
  the issuer's signed payload, which is public from the moment
  the bundle is emitted. No CSPRNG. Verification is
  deterministic and replay-safe (the bundle metadata includes
  `issuance_timestamp`, signed; replaying an old bundle is
  visible by its timestamp).

### `BoundedRange` (wire-tag `0x0003`, gated `#[cfg(feature = "bounded-range-proof")]`)

- **Crate path:** `dark-confidential::disclosure::bounded_range`
- **Function:** `pub fn verify_amount_bounded(commitment:
  &ValueCommitment, max: u64, proof: &BoundedRangeProof,
  issuer_pk: &PublicKey, bundle_metadata: &BundleMetadata) ->
  Result<BoundedRangeVerification>`
- **Construction:**
  1. Schnorr verify (BIP-340, tag
     `dark-confidential/disclosure/bounded-range/v1`) over
     `(commitment_bytes || max_be8 || proof_bytes ||
     bundle_metadata_bytes)`.
  2. `let inclusive = range_proof::verify_range_bounded(
     commitment, proof.inner())?;` — the existing entry point in
     `crates/dark-confidential/src/range_proof.rs`.
  3. Assert `inclusive.end() <= max` (and, for the two-sided
     variant, `inclusive.start() >= min`); reject otherwise.
  4. The bundle MUST carry the prover-intended `(min_bits, exp)`
     so the verifier rejects a witness whose Back-Maxwell
     auto-sized range exceeds `max` even though the *real*
     amount was below it. This is a specific defence against
     the range-widening behaviour documented in
     `range_proof.rs`'s `verify_range_bounded` comment.
- **Crate-resident dependency surface:** `secp256k1-zkp = 0.11`
  (range proof verify), `secp256k1 = 0.29` (signature verify).
- **Implementation issue:** #566 (`prove_amount_bounded`,
  `verify_amount_bounded`, plus two-sided
  `prove_amount_in_range` / `verify_amount_in_range`).
- **Audit notes:** the verifier inherits ADR-0001's audit
  posture for range proofs. No new primitive is introduced.
  The `<= max` integer check is constant-time on `u64`.

### `SourceOfFunds` (wire-tag `0x0004`, gated `#[cfg(feature = "source-of-funds-proof")]`, default-off at CV-M6 ship gate)

- **Crate path:**
  `dark-confidential::disclosure::source_of_funds`
- **Function:** `pub fn verify_source_chain(bundle:
  &SourceOfFundsBundle, issuer_pk: &PublicKey, public_state:
  &PublicCommitmentState, max_depth: u8) ->
  Result<SourceOfFundsVerification>`
- **Construction:**
  1. Schnorr verify (BIP-340, tag
     `dark-confidential/disclosure/source-of-funds/v1`) over
     the canonical-encoded chain.
  2. For each link, recompute the nullifier per ADR-0002
     (`nullifier::derive`) and check it appears in the
     public nullifier-set commitment for the link's round.
     Per-link Merkle inclusion against the round commitment
     uses the existing round-tree path verifier from
     `dark-confidential::vtxo` / the round-commitment ADR.
  3. Verify chain endpoints match the bundle's claimed
     `(target_vtxo_id, ancestor_vtxo_id)`.
- **Crate-resident dependency surface:** `secp256k1 = 0.29`,
  `hmac = 0.12`, `sha2 = 0.10` (per
  `crates/dark-confidential/src/nullifier.rs`).
- **Implementation issue:** #567.
- **Audit notes:** this is the only v1 type that does
  cross-round graph reads. The verifier MUST cap chain length
  at `max_depth` (bundle field, additionally bounded at
  parser layer to a hard 256-hop limit) to bound verifier
  work. Replay across forks/chains is prevented by the
  signature binding `(chain_canonical_bytes,
  network_genesis_round_id)`.

## Backwards compat

The shipping enum is closed for v1; the **forward-compat rules**
ensure a v2 type can land additively without invalidating v1
verifiers or v1 bundles.

### Tag-stability rule

Wire-tag bytes are forever associated with the algorithm they
were minted against. Reserved tags (`0x0005`, `0x0006`, `0x0007`
in this ADR) are pre-claimed and MUST NOT be reassigned. A
verifier that encounters a reserved tag whose verifier is not
present in its build (because the feature flag was off, or
because a future v2 type has not been compiled in) emits
`ProofVerifyError::UnknownProofType { tag }`; this is the same
error path as a literally-unknown tag. The bundle-format ADR
(#562) makes the unknown-tag rejection mandatory; this ADR
ensures reserved-but-not-implemented behaves identically.

### v2 additive types (new tag, new verifier)

A v2 ADR ships a new proof type by:

1. Picking the next free `u16` (e.g. `0x0008` for the first
   v2-introduced type, after the v1 reservations).
2. Naming the verifier function with a `_v2` suffix or a fresh
   module path. Example: `dark-confidential::disclosure::
   bounded_range_v2::verify_amount_bounded_v2`.
3. Tagging the new transcript hash with `_v2` in its
   domain-separation tag (e.g.
   `dark-confidential/disclosure/bounded-range/v2`).
4. Updating the proof-type enum's `From<u16>` impl to recognise
   the new tag.
5. v1 verifiers, **without recompilation**, continue to handle
   v1 tags unchanged. v1 bundles emitted at any point in the
   future still verify under v1 verifiers.

### v2 type-replacement (deprecate v1 tag in favour of v2 tag)

A v2 ADR may *deprecate* a v1 tag (e.g. swap Back-Maxwell range
proofs for Bulletproofs) by:

1. Minting the replacement tag (e.g. `0x0009` for
   `BoundedRangeBulletproofs`).
2. Updating the prover side of the workspace to emit the new
   tag.
3. Leaving the old verifier in `dark-confidential` indefinitely
   (verifier code is small; the tag-enum case stays). v1
   bundles emitted by older provers continue to verify forever.
4. **Not** reusing the old tag for the new construction. The
   old tag remains pinned to Back-Maxwell verification for the
   lifetime of the protocol.

### v2 field-additivity inside an existing tag

A v2 ADR may extend an existing bundle layout with a new
*optional* field (e.g. an additional metadata column) only if
all three conditions hold:

1. The field is encoded in CBOR (per #562's bundle envelope) as
   a new map key at a position that older verifiers ignore by
   construction (CBOR's deterministic-encoding rule sorts map
   keys; appending higher-numbered keys is invisible to a
   verifier that only reads keys it knows).
2. The new field does NOT change the signature-transcript
   bytes — i.e. the issuer's signature input is over the v1
   subset of fields. (Otherwise old verifiers reject the
   updated bundle's signature.)
3. The semantic meaning of the v1 fields is unchanged.

Field-additivity is **not** the path for cryptographic
construction changes. Construction changes mint a new tag.

### Deferred-tag activation

Tag `0x0004` (`SourceOfFunds`) ships reserved + feature-flag-
gated. Activating it does NOT require an ADR amendment; the
flip is editorial (the feature flag's `default = ["..."]` list
in `dark-confidential/Cargo.toml` adds `source-of-funds-proof`
once #567 lands and the verifier passes the audit gate). v1
verifiers compiled without the feature continue to reject the
tag with `UnknownProofType`; that's the documented behaviour,
not a regression.

A v2 of `SourceOfFunds` (e.g. with stronger graph-anonymity
properties) mints a new tag per the rules above.

## Cross-cutting — constraints on downstream issues

These are not suggestions; they are requirements for this ADR's
soundness. Any deviation must reopen this ADR before landing.

### #565 (VTXO selective reveal) MUST

- Implement `reveal_vtxo(vtxo_id, amount, blinding) ->
  VtxoRevealProof` and `verify_vtxo_reveal(proof, commitment)
  -> bool` (issue API) under
  `dark-confidential::disclosure::vtxo_reveal`. Re-export the
  verifier under the `verify_vtxo_reveal` name fixed in
  "Verifier-algorithm pinning" above.
- Use wire-tag `0x0002` for the bundle envelope's `proof_type`
  field. The tag MUST NOT be configurable.
- Sign the bundle with the user's `spend_pk` (per ADR-M5-DD-
  stealth-derivation) using BIP-340 Schnorr with the
  domain-separation tag
  `dark-confidential/disclosure/vtxo-reveal/v1`.
- Embed `(vtxo_id, amount, blinding)` plus
  `(issuance_timestamp, scope_metadata)` in the signed
  payload, in that order, under the canonical CBOR encoding
  defined by #562.
- Reuse `commitment::PedersenCommitment` from
  `crates/dark-confidential/src/commitment.rs` as the binding
  primitive. MUST NOT introduce a parallel commitment type.
- Document explicitly in module-level rustdoc that revealing
  one VTXO does NOT reveal sibling VTXOs, descendants, or
  ancestors — and that the *user* must understand the linkable-
  graph property of nullifiers (per ADR-0002) which means a
  VTXO reveal can be correlated with sibling VTXOs *if and
  only if* the verifier already has the graph (which they do,
  from public on-chain data, but they had it before the
  reveal too).
- Provide negative tests:
  - `wrong_blinding_fails_verification` — perturb `blinding`
    by one bit; verifier rejects.
  - `wrong_amount_fails_verification` — flip a bit in
    `amount`; verifier rejects.
  - `wrong_issuer_signature_fails_verification` — sign with
    an unrelated key; verifier rejects.
  - `replayed_bundle_for_different_vtxo_fails` — substitute
    `vtxo_id` after signing; signature breaks.

### #565 MUST NOT

- Use any commitment scheme other than the one in
  `crates/dark-confidential/src/commitment.rs`. The range-proof
  module's `ValueCommitment` is intentionally byte-incompatible
  (per its module rustdoc) and MUST NOT be substituted.
- Reuse the wire-tag `0x0001` (viewing-key) or `0x0003`
  (bounded-range).
- Embed a `proof_type_string: String` field and parse it
  case-insensitively. The wire-tag is the single source of
  truth.
- Introduce an unauthenticated reveal mode (i.e. reveal
  without an issuer signature). Every bundle is signed.

### #566 (bounded-range compliance proofs) MUST

- Implement `prove_amount_bounded(amount, blinding, max) ->
  BoundedRangeProof` and `verify_amount_bounded(commitment,
  max, proof) -> bool` (issue API) under
  `dark-confidential::disclosure::bounded_range`.
- Use wire-tag `0x0003`.
- Gate the entire module behind `#[cfg(feature =
  "bounded-range-proof")]`. Default-on at the CV-M6 ship gate
  (the feature is in `dark-confidential`'s
  `[features].default` list); off-by-default builds for
  audit/stage tooling pass `--no-default-features` to drop the
  module.
- Reuse the existing `range_proof::verify_range_bounded` entry
  point on the verifier path. The bounded-range verifier is a
  thin wrapper that adds the `<= max` (and optional `>= min`)
  comparison.
- Embed the prover-intended `(min_bits, exp)` parameters in the
  bundle and reject witnesses whose Back-Maxwell auto-sized
  range exceeds the claimed `max`. This closes the
  range-widening gap documented in `range_proof.rs`'s
  module-level rustdoc.
- Sign with BIP-340 Schnorr, tag
  `dark-confidential/disclosure/bounded-range/v1`. Signed
  payload order is `(commitment_bytes || max_be8 ||
  proof_bytes || min_bits_u8 || exp_u8 ||
  bundle_metadata_bytes)`.
- Document the proof size and proving-time targets per the
  issue's acceptance criterion ("proof size documented;
  proving time <500 ms"). Targets are *informational* in this
  ADR; the issue is responsible for enforcing them via
  Criterion benches with a regression threshold.
- Provide a property test over uniformly-random
  `(amount, max)` pairs covering both the satisfiable
  (`amount < max`) and unsatisfiable (`amount >= max`,
  prover MUST refuse) regimes.

### #566 MUST NOT

- Substitute Bulletproofs for Back-Maxwell at the v1 wire-tag.
  Bulletproofs migration is FU-BP per ADR-0001 and lands as a
  *new* wire-tag (e.g. `0x0009 BoundedRangeBulletproofs`),
  NOT a swap under `0x0003`.
- Verify a bundle whose embedded `(min_bits, exp)` produce a
  Back-Maxwell verified range exceeding `max`. The check is
  not optional.
- Treat the absence of the feature flag as a "soft failure"
  that returns `false` from the verifier. The verifier
  function MUST NOT compile when the feature is off; calling
  code MUST guard with `#[cfg(...)]` or a runtime
  `ProofVerifyError::FeatureNotEnabled` from a thin shim.
- Couple the bounded-range verifier to the source-of-funds
  module. The two are independent.

### #567 (source-of-funds proofs over the linkable graph) MUST

- Implement `prove_source_chain(vtxo_id, ancestor_vtxo_id,
  max_depth) -> SourceOfFundsProof` and a verifier under
  `dark-confidential::disclosure::source_of_funds::
  verify_source_chain`.
- Use wire-tag `0x0004`.
- Gate behind `#[cfg(feature = "source-of-funds-proof")]`.
  Default-OFF at the CV-M6 ship gate. The feature flips to
  default-on in a follow-up release once #567's verifier and
  end-to-end tests have run on regtest for at least one
  release cycle.
- Re-derive nullifiers via the existing
  `dark-confidential::nullifier::derive` (per ADR-0002). MUST
  NOT introduce a parallel nullifier scheme.
- Cap chain length at `max_depth ≤ 256` at the parser layer.
  Bundles with `max_depth > 256` are rejected as
  `InvalidEncoding` before any signature check.
- Bind the issuer signature to
  `(target_vtxo_id || ancestor_vtxo_id ||
  chain_canonical_bytes || network_genesis_round_id)`. The
  `network_genesis_round_id` binding prevents a chain emitted
  on regtest from being replayed against mainnet (and vice
  versa).
- Document the *amount-revelation properties* per the issue's
  acceptance criterion: amounts at intermediate hops are NOT
  revealed; only the chain shape and the per-link nullifier
  identity are. The bundle MUST NOT carry intermediate
  amounts; if it did, those would land in the issuer-signed
  payload and propagate to verifiers.
- Provide negative tests:
  - `forged_hop_rejected` — substitute one link's
    `output_vtxo` for an unrelated VTXO; verifier rejects.
  - `cycle_in_chain_rejected` — chain that loops back to an
    earlier hop; verifier rejects (cycles are an explicit
    failure mode).
  - `cross_chain_replay_rejected` — emit on regtest, present
    on mainnet; signature transcript mismatch rejects.
  - `truncated_chain_rejected` — strip the final link;
    endpoint-equality check rejects.

### #567 MUST NOT

- Carry intermediate-hop amounts in the bundle.
- Allow a verifier to accept a chain whose endpoints don't
  match the bundle's claimed
  `(target_vtxo_id, ancestor_vtxo_id)`.
- Use any nullifier derivation other than the one in
  `crates/dark-confidential/src/nullifier.rs` /
  `docs/adr/0002-nullifier-derivation.md`.
- Ship default-on at the CV-M6 release. The feature flag is
  the gate.

### #568 (`ark-cli` disclose/verify commands) MUST

- Expose one subcommand per shipping wire-tag:
  - `ark-cli disclose viewing-key --scope <round-range>` —
    emits a `0x0001` bundle (#564 + #561).
  - `ark-cli disclose reveal-vtxo <vtxo_id>` — emits a
    `0x0002` bundle (#565).
  - `ark-cli disclose prove-range <vtxo_id> --max <amount>` —
    emits a `0x0003` bundle (#566). Available only in builds
    with `bounded-range-proof` feature compiled in.
  - `ark-cli disclose prove-source <vtxo_id> --back-to <round>`
    — emits a `0x0004` bundle (#567). Available only in builds
    with `source-of-funds-proof` feature compiled in; the CLI
    surface MUST detect the feature absence and print a clear
    "feature not enabled" message rather than fail-with-stack-
    trace.
- Expose `ark-cli verify-proof <bundle_path>` (and stdin
  variant) that:
  - Decodes the bundle envelope (#562).
  - Extracts `proof_type` (u16 BE).
  - Dispatches to the matching verifier per "Verifier-
    algorithm pinning" above.
  - Returns a structured result on stdout (`--json` flag) or
    a human-readable summary by default.
  - On unknown / reserved-but-disabled tag, prints
    `error: unknown proof type 0x{:04X}; this CLI was built
    without support for it` and exits with status 2 (per the
    issue's "structured error, not a crash" criterion).
- Document each subcommand with at least one example in
  `--help`.

### #568 MUST NOT

- Hardcode the verifier algorithm in the CLI. The CLI
  dispatches via wire-tag → verifier-function mapping; new
  types added under "Backwards compat" land by re-running the
  same dispatch table.
- Accept a bundle whose `proof_type` is `0x0000`; that's
  reserved as invalid per "Decision".
- Print raw bytes of the issuer signature on the human-
  readable summary by default. Signature bytes are noisy and
  uninteresting; `--json` includes them.

### #569 (`VerifyComplianceProof` gRPC endpoint) MUST

- Be unauthenticated (the bundle carries its own issuer
  signature; the operator does not need to authenticate the
  caller). Rate-limited at the IP/network layer per the
  issue's acceptance criterion.
- Implement the same dispatch table as #568:
  `bundle.proof_type → verifier_function`.
- Return a structured `VerificationResult { accepted: bool,
  proof_type: u16, details: oneof<...> }` in the proto
  schema. The `details` oneof has one arm per shipping wire-
  tag (per "Verifier-algorithm pinning"), each carrying the
  structured fields the human-readable summary would render.
- On unknown / reserved-but-disabled tag, return a typed
  `UnknownProofType { tag: u32 }` (gRPC `INVALID_ARGUMENT`)
  rather than crashing.
- Audit-log every verification request with
  `(timestamp, caller_ip, proof_type, bundle_size_bytes,
  result)` per the issue's observability acceptance criterion.
  The log MUST NOT capture the bundle bytes (privacy: bundles
  may contain viewing keys; logging them would re-introduce
  the operator-as-custodian property the protocol avoids).

### #569 MUST NOT

- Re-implement any verifier. The endpoint MUST link against
  `dark-confidential::disclosure` and call the pinned verifier
  functions. Drift between the CLI and the gRPC verifier is a
  bug class this ADR rules out by construction.
- Cache verification results across requests. Each request is
  stateless; replay-detection is the bundle's responsibility
  (issuance_timestamp + signature transcript).
- Hold any secret material in the verification path. The
  endpoint runs against public on-chain data only.

### Documentation MUST

- Ship a `docs/compliance/selective-disclosure.md` (per #570)
  that, for each shipping wire-tag, documents:
  - What the proof discloses to the verifier.
  - What it does NOT disclose.
  - The institutional use case it covers.
  - A worked end-to-end example using `ark-cli`.
- Render the deferred set with explicit "not available at
  launch; tracked under [FU-DT-*]" callouts so an integrator
  reading the doc cannot mistake a deferred type for a
  shipping one.
- Be reviewed by someone with a compliance background per
  #570's acceptance criterion.

## Open Questions / TODO

- **Scope-encoding granularity for `ViewingKeyIssuance`.** This
  ADR pins the wire-tag and verifier function but defers the
  scope-bound encoding (round range vs. time range vs. epoch)
  to ADR `m6-dd-viewing-scope` (#561), which lands in parallel.
  If #561's outcome is "scope is a `(round_id_start,
  round_id_end_exclusive)` pair", the bundle layout is
  trivially compatible. If #561 picks a time-based scheme, the
  bundle MUST carry a `scope_kind` discriminator inside the
  v1 viewing-key payload — and that's a v1.1 amendment to this
  ADR's signed-payload format, NOT a wire-tag change.
  Tracked as **[FU-DT-VIEWING-SCOPE-ENCODING]**.

- **`AggregateBalanceThreshold` lift.** Reserved tag `0x0005`,
  not implemented in v1. The construction is "homomorphic sum
  of commitments + range proof on
  `(C_sum - threshold·G)`". The follow-up ADR must pin (a)
  the set of commitments the user is asserting (one VTXO, all
  VTXOs the user controls, an explicit allowlist?), (b) how
  the verifier obtains the public commitments (from the bundle
  inline, or from public on-chain state by VTXO id), and (c)
  whether the proof carries one aggregated range proof or N
  individual ones. Tracked as **[FU-DT-AGG-BALANCE]**.

- **`SetMembershipNotInSanctioned` governance.** Reserved tag
  `0x0006`, not implemented in v1. The cryptographic surface
  (Merkle accumulator vs. zk set-non-membership) and the
  governance surface (whose sanctioned list?) are both open.
  This is intentionally out of scope for the cryptography
  workstream; the ADR amendment that lands it will need
  explicit sign-off from the compliance/governance side. Tracked
  as **[FU-DT-SANCTIONED-NONMEMBER]**.

- **`MultiProofEnvelope` composition.** Reserved tag `0x0007`,
  not implemented in v1. Composing N sub-proofs in one
  envelope reduces wire size and gives the verifier a single
  acceptance gate, but interacts non-trivially with the
  unknown-tag rejection rule (does an envelope reject if one
  sub-proof's tag is unknown? does it accept the rest?). The
  follow-up ADR must pin the
  any-unknown-rejects-everything vs. partial-acceptance
  semantics. Tracked as **[FU-DT-MULTIPROOF-ENVELOPE]**.

- **`SourceOfFunds` default-on flip.** Tag `0x0004` ships
  reserved + feature-flag-gated default-OFF. The criteria for
  flipping `source-of-funds-proof` to default-on (one regtest
  release cycle, end-to-end tests passing, the CV-M6 release-
  manager's sign-off) are recorded in the issue but not yet in
  a release-checklist document. Tracked as
  **[FU-DT-SOURCE-DEFAULT-ON]**.

- **Bulletproofs migration of `BoundedRange`.** ADR-0001's
  FU-BP captures the underlying primitive migration; this ADR
  fixes the wire-tag-stability rule (FU-BP lands as a new
  wire-tag, not a re-pointing of `0x0003`). Tracked here as
  **[FU-DT-BP-WIRE-TAG]** for cross-reference; the cryptographic
  work itself is FU-BP.

- **Cross-implementation test-vector exchange.** Once a second
  implementation of the disclosure verifiers exists (e.g. a
  Python or TypeScript verifier in a partner SDK), each
  shipping wire-tag MUST have a `docs/adr/vectors/m6-dd-
  disclosure-types-vectors.json` entry that the second
  implementation runs against and byte-matches. Tracked as
  **[FU-DT-VECTOR-XCHECK]**.

- **Bundle-size bounds.** The bundle envelope's outer-layer
  size limit (#562) interacts with `SourceOfFunds`'s
  per-link-Merkle-path payload, which dominates wire size for
  long chains. The ADR `m6-dd-proof-bundle` (under #562) is
  responsible for picking the limit; this ADR documents that
  `SourceOfFunds` payloads are the largest among the v1 set.
  Tracked as **[FU-DT-BUNDLE-SIZE]**.

- **Privacy: viewing-key bundles are leakable.** A user who
  emits a `ViewingKeyIssuance` bundle to a chosen verifier
  cannot prevent that verifier from forwarding the viewing
  key to a third party. This is inherent to the construction
  (the bundle IS the credential) and not a bug in this ADR;
  the compliance guide (#570) MUST surface it. Tracked as
  **[FU-DT-VK-FORWARDABILITY-DOC]** — documentation only,
  not a cryptographic change.

- **`spend_pk` as the issuer-signing key.** This ADR pins the
  issuer signature to the user's `spend_pk` derived per
  ADR-M5-DD-stealth-derivation. A user with multiple stealth
  accounts (different `account` indices) emits one bundle per
  account they're disclosing about. Whether to allow a single
  bundle to span multiple accounts (e.g. with one signature
  per account inside a `MultiProofEnvelope`) is a v2 design
  question. Tracked as **[FU-DT-MULTI-ACCOUNT-DISCLOSURE]**.

## References

- Issue #563 (this ADR)
- Issue #561 — Viewing key scope mechanism (parallel ADR
  `m6-dd-viewing-scope`; pins the scope encoding this ADR
  consumes for `ViewingKeyIssuance`)
- Issue #562 — Compliance proof bundle format (parallel ADR
  `m6-dd-proof-bundle`; pins the outer envelope this ADR
  populates)
- Issue #564 — Viewing key derivation and scoped access
  (consumer of wire-tag `0x0001`)
- Issue #565 — VTXO selective reveal with commitment opening
  (consumer of wire-tag `0x0002`)
- Issue #566 — Bounded-range compliance proofs (consumer of
  wire-tag `0x0003`)
- Issue #567 — Source-of-funds proofs over the linkable graph
  (consumer of wire-tag `0x0004`, deferred default-OFF)
- Issue #568 — `ark-cli` disclose/verify commands (CLI surface
  binding all four wire-tags)
- Issue #569 — `VerifyComplianceProof` gRPC endpoint (server
  surface binding all four wire-tags)
- Issue #570 — Compliance guide for institutional users
  (documentation consumer)
- Issue #520 — Go `arkd` E2E parity gate (transparent paths
  unaffected by this ADR)
- ADR-0001 — secp256k1-zkp integration strategy (range-proof
  primitive; FU-BP migration path that this ADR's wire-tag
  rules accommodate)
- ADR-0002 — Nullifier derivation scheme and domain separation
  (graph-link primitive that `SourceOfFunds` consumes)
- ADR-0003 — Confidential VTXO memo format (memo-decryption
  primitive that `ViewingKeyIssuance` consumes)
- ADR-M5-DD — Stealth-address derivation (defines
  `MetaAddress`, `scan_pk`, `spend_pk`; latter is the issuer-
  signing key for every bundle)
- ADR-M5-DD-announcement-pruning (the round-id range that
  scopes a viewing-key bundle is the same round-id namespace
  this ADR uses)
- `crates/dark-confidential/src/disclosure.rs` — module the v1
  verifier functions live in (currently a stub)
- `crates/dark-confidential/src/commitment.rs` — Pedersen
  commitments consumed by `VtxoReveal` and `BoundedRange`
- `crates/dark-confidential/src/range_proof.rs` —
  `verify_range_bounded` consumed by `BoundedRange`
- `crates/dark-confidential/src/nullifier.rs` —
  `derive` consumed by `SourceOfFunds`
- `crates/dark-confidential/src/balance_proof.rs` — BIP-340
  Schnorr conventions reused for issuer signatures
- BIP-340 — Schnorr signatures (issuer-signature scheme,
  tagged-hash construction reused throughout)
- Test vectors:
  `docs/adr/vectors/m6-dd-disclosure-types-vectors.json`
  (created by the implementation issues; populated per type
  as it ships)
