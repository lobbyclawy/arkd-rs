# ADR-0002: Nullifier derivation scheme and domain separation

- **Status:** Proposed
- **Date:** 2026-04-22
- **Milestone:** CV-M1 (Confidential Crypto Primitives)
- **Drives:** #522 -> unblocks #530, #538, #539
- **Affects:** confidential spent-set semantics; transparent paths untouched (#520 parity gate)

## Context

Confidential VTXOs need a deterministic nullifier so the spent set can reject
replays without revealing the underlying secret key or exposing extra structure
about the VTXO graph. The issue asks us to choose the primitive, the domain
separation format, and where versioning lives.

The nullifier must be:

- deterministic: the same `(secret_key, vtxo_id)` pair always yields the same output
- collision resistant across distinct inputs
- one-way with respect to the secret key
- cheap to compute in every client and server implementation
- stable across restore and multi-language implementations

Candidate constructions from #522:

1. `SHA256(dst || secret_key || vtxo_id)`
2. `HMAC-SHA256(secret_key, dst || vtxo_id)`
3. `H(secret_key * H_point(vtxo_id))` (curve-based)

## Decision

Use **HMAC-SHA256** with the confidential spend key as the HMAC key and a
versioned domain-separated message as the input:

```text
nullifier = HMAC-SHA256(
  key = secret_key_bytes,
  msg = dst || version || vtxo_id_bytes,
)
```

Where:

- `secret_key_bytes` is the 32-byte confidential spend secret key encoding
- `dst = "dark-confidential/nullifier"`
- `version = 0x01`
- `vtxo_id_bytes` is the canonical binary encoding of the VTXO identifier
- the resulting nullifier is the full 32-byte HMAC output

## Encoding details

### Domain separation

The domain separator is the ASCII byte string:

```text
"dark-confidential/nullifier"
```

The message layout is:

```text
msg = b"dark-confidential/nullifier" || 0x00 || version || vtxo_id_bytes
```

The zero byte is a hard separator so future suffixes on the DST cannot collide
with a version-prefixed encoding.

### Version location

The **version byte lives inside the message**, not in the key and not prepended
to the final nullifier value. That gives us algorithm agility without changing
stored nullifier width or database columns.

Current version:

- `NULLIFIER_VERSION_V1 = 0x01`

### Canonical VTXO identifier bytes

`vtxo_id_bytes` must be the canonical binary form used everywhere in
`dark-confidential`. For ADR purposes this is defined as:

```text
32-byte txid || 4-byte big-endian vout
```

If confidential VTXOs later adopt a richer internal identifier, that richer
identifier must still be serialized into a unique canonical byte string before
nullifier derivation. Callers do not get to invent ad hoc encodings.

## Why HMAC-SHA256

### Versus raw SHA256(dst || sk || vtxo_id)

Raw concatenation hashing is viable, but HMAC is a cleaner keyed construction.
It removes ambiguity about where the secret belongs in the transcript and avoids
future mistakes where implementations accidentally vary concatenation framing.

### Versus curve-based derivation

A curve-based nullifier is more complex, harder to audit, and does not buy us
anything essential for CV-M1. We need a stable pseudorandom identifier, not a
public-key primitive. HMAC-SHA256 is standard, fast, portable, and easy to test
across Rust, Go, TypeScript, and future wallet environments.

## Test vectors

The implementation must ship test vectors generated from this exact transcript.
The required committed vector set is:

### Vector A

- secret key (hex): `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- vtxo id (hex): `111111111111111111111111111111111111111111111111111111111111111100000001`
- version: `01`
- dst: `dark-confidential/nullifier`

### Vector B

- secret key (hex): `1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100`
- vtxo id (hex): `22222222222222222222222222222222222222222222222222222222222222220000000a`
- version: `01`
- dst: `dark-confidential/nullifier`

### Vector C

- secret key (hex): `ffffffffffffffffffffffffffffffff00000000000000000000000000000001`
- vtxo id (hex): `abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd00000002`
- version: `01`
- dst: `dark-confidential/nullifier`

When `dark-confidential` lands, these vectors must be materialized as concrete
expected nullifier outputs in unit tests. This ADR locks the transcript format;
it does not leave room for implementation-specific reinterpretation.

## Failure-mode analysis

### Secret key reuse

If a user reuses the same secret key across many VTXOs, nullifiers remain
independent as long as `vtxo_id_bytes` are unique. Reuse does mean the same key
anchors the entire spent-set lineage for that wallet, so compromise of the key
lets an attacker recompute every historical nullifier for known VTXO IDs.
That is acceptable and expected: nullifiers are spend markers, not encryption.

### VTXO ID collision

If two distinct VTXOs are serialized to the same canonical `vtxo_id_bytes`, they
will yield the same nullifier for a given secret key. Therefore canonical VTXO
ID encoding is consensus-critical for confidential spend safety. Downstream
issues must define and test that encoding centrally.

### Secret key leak

If the spend secret key leaks, nullifier privacy is lost for every VTXO ID the
attacker knows or can derive. That does **not** let the attacker forge a second
nullifier for the same input or create a collision more cheaply than brute force;
it does let them correlate known VTXO IDs with spent-set entries. This is an
acceptable failure mode because key compromise already means spend authority is
lost.

## Consequences

### Positive

- simple, portable, and fast to implement
- no new curve assumptions beyond the existing spend key material
- fixed 32-byte output fits storage and proto surfaces cleanly
- versioning is built in without widening the nullifier

### Negative

- nullifiers are not algebraic objects, so we cannot reuse them for proof
  systems that expect curve points
- confidentiality depends on correct canonical VTXO ID encoding elsewhere
- migrating to another primitive later requires an explicit new version byte

## Constraints on downstream issues

- **#530** must treat nullifiers as opaque 32-byte values, not structured hashes
- **#538** must derive nullifiers only through one central helper in
  `dark-confidential`
- **#539** must persist the 32-byte output exactly and compare bytes exactly
- any future primitive change must mint a new version byte, not reinterpret v1
