# Confidential Transactions: SDK Integrator Guide

- **Audience:** wallet authors, custodial integrators, exchange engineers, and anyone building on top of `dark-client` who needs to send or receive Confidential VTXOs.
- **Scope:** end-to-end walkthrough of building a confidential payment with the Rust SDK, from wallet creation to broadcast. Includes how range proofs, balance proofs, and nullifiers compose, and which fields are encrypted on disk.
- **Status:** living document; tracks main. Functions called out as "shipping in #572" are part of the `create_confidential_tx` work item that lands at the same milestone (CV-M7) as this guide.
- **Companion documents:**
  - [Migration: Transparent → Confidential](../migration/transparent-to-confidential.md)
  - [Confidential Threat Model](../security/confidential-threat-model.md)

---

## 1. Mental model

A confidential VTXO replaces three pieces of public data on a transparent VTXO with cryptographic stand-ins:

| Public on a transparent VTXO | Hidden on a confidential VTXO | How it is hidden |
| --- | --- | --- |
| Amount in satoshis | Pedersen commitment `C = amount·G + blinding·H` | `PedersenCommitment::commit`, see ADR-0001 |
| Owner pubkey | Stealth one-time output key derived per-payment | `MetaAddress` + sender ECDH, see ADR-M5-DD |
| Spend linkage by outpoint | Nullifier (one-way, owner-derived) | `derive_nullifier`, see ADR-0002 |

Three additional pieces of data ride on every confidential output so that the operator can verify the round without seeing amounts:

- **Range proof.** Each confidential output proves its committed amount lies in `[0, 2^63 − 1]`. Without this, a malicious sender could commit to a field-wrapped negative amount and inflate supply. See ADR-0001.
- **Balance proof.** The whole transaction proves `Σ C_in − Σ C_out − fee·G = excess·H` for an excess scalar the sender knows. The operator checks balance homomorphically without ever learning amounts.
- **Encrypted memo.** The recipient needs the cleartext `(amount, blinding)` to spend the VTXO later. The sender ECDH's against the recipient's scan key, derives an AEAD key, and packs the opening into a 72-byte plaintext that only the recipient can decrypt. See ADR-0003.

Everything else — round-tree placement, exit script, gRPC envelope — works exactly the same as for transparent VTXOs. Mixed transparent/confidential rounds are a first-class case (see #541 and the transparent-only Go-`arkd` parity gate at #520, both honoured by the round tree at #540).

---

## 2. Hello world: send a confidential payment

The end-to-end flow has six steps. Steps 1–2 are wallet bring-up; 3–4 are address exchange; 5–6 are the actual send.

```rust,no_run
use bitcoin::Network;
use dark_client::sdk::ArkSdk;
use dark_client::wallet::SingleKeyWallet;
use dark_confidential::stealth::{MetaAddress, StealthNetwork};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // (1) Bring up an SDK instance against a regtest operator.
    let mut sdk = ArkSdk::generate(
        "http://localhost:50051",      // gRPC operator
        "http://localhost:3000",       // Esplora-compatible explorer
        Network::Regtest,
    );
    sdk.init().await?;

    // (2) Derive the stealth meta-address. In practice this comes
    //     from the same BIP-39 mnemonic that fed the SingleKeyWallet.
    let seed: [u8; 32] = /* from BIP-39 seed */ [0u8; 32];
    let (meta, secrets) = MetaAddress::from_seed(
        &seed,
        /*account_index=*/0,
        StealthNetwork::Regtest,
    )?;

    // (3) Print the meta-address so the recipient can paste it in.
    //     Format: bech32m, e.g. "rdarks1...". See ADR-M5-DD.
    println!("my meta-address: {}", meta.to_bech32m());

    // (4) Receive a meta-address from the counterparty.
    let recipient = MetaAddress::from_bech32m(
        "rdarks1qfgr...your-counterparty...",
    )?;

    // (5) Build & submit a confidential payment. (Function name
    //     pending #572 — see "Send path: APIs that ship in #572".)
    let amount_sats: u64 = 50_000;
    let fee_sats:    u64 =    250;

    // sdk.send_confidential(&recipient, amount_sats, fee_sats).await?;

    // (6) Display balance.
    let balance = sdk.balance().await?;
    println!("offchain balance: {} sats", balance.offchain.total);

    Ok(())
}
```

The `SingleKeyWallet` already shipping in `dark-client` (`crates/dark-client/src/wallet.rs`) is the transparent half: it generates the secp256k1 keypair used for taproot key-path signing and BIP-322 ownership proofs. The stealth half (scan key + spend key + viewing key) comes from `dark-confidential` and lives next to the transparent key under disjoint BIP-32 derivation paths, per ADR-M5-DD.

### What `MetaAddress::from_seed` produces

`MetaAddress::from_seed(seed, account_index, network)` returns a tuple `(MetaAddress, StealthSecrets)` where:

- `MetaAddress` is the **publishable** half: two compressed secp256k1 public keys plus a network discriminator, encoded as bech32m with HRP `darks` / `tdarks` / `rdarks`. The bech32m payload is `[ version: u8 ][ scan_pk: 33 ][ spend_pk: 33 ]` (ADR-M5-DD).
- `StealthSecrets { scan_key, spend_key }` is the **secret** half. `ScanKey` and `SpendKey` are `Zeroize`-on-drop wrappers and intentionally do **not** implement `Copy`, `Clone`, or `Debug` — see `crates/dark-confidential/src/stealth/keys.rs`. The only way to get the bytes out is `expose_secret()`, which is the audit anchor (`grep expose_secret` finds every disclosure site).

> The scan key is read-only. Anyone holding it can detect every incoming VTXO addressed to the meta-address but cannot spend. The spend key is full spending authority. Treat the spend key with the same care you treat the wallet's main private key today.

### Send path: APIs that ship in #572

The high-level send call is `dark_client::create_confidential_tx`, gated on issue **#572** (Confidential transaction builder in `dark-client`). Its signature is fixed:

```text
create_confidential_tx(
    inputs:  &[OwnedVtxo],
    outputs: &[(MetaAddress, u64)],
    fee:     u64,
) -> Result<ConfidentialTransaction>
```

Internally it executes the steps below. Each step is callable today as a primitive, so integrators with custom batching needs can wire them up directly against `dark-confidential`:

| Step | Primitive | Crate location |
| --- | --- | --- |
| Compute nullifiers for inputs | `nullifier::derive_nullifier` | `dark-confidential::nullifier` |
| Derive output blindings | wallet-deterministic, seed + vtxo index | wallet code |
| Derive stealth one-time keys | `stealth::sender::derive_one_time_output` | `dark-confidential::stealth::sender` |
| Build Pedersen commitments | `commitment::PedersenCommitment::commit` | `dark-confidential::commitment` |
| Aggregated range proof | `range_proof::RangeProof::prove_aggregated` | `dark-confidential::range_proof` |
| Balance proof | `balance_proof::prove_balance` | `dark-confidential::balance_proof` |
| Encrypt memo per output | `crate::confidential_memo::encrypt` | per ADR-0003 |

Until #572 lands on `main`, integrators can compose the primitives directly. The pseudocode below walks through it; every function name is real.

```rust,ignore
use dark_confidential::commitment::PedersenCommitment;
use dark_confidential::nullifier::{derive_nullifier, VtxoId};
use dark_confidential::stealth::{MetaAddress, sender::derive_one_time_output};

// Per input: derive nullifier from the spend secret + VTXO id (ADR-0002).
for input in &inputs {
    let nullifier = derive_nullifier(&input.spend_secret, &VtxoId::from(input.outpoint));
    // attach to the spend descriptor
}

// Per output: derive a one-time output key, then commit to the amount.
for (recipient_meta, amount) in &outputs {
    let stealth_out = derive_one_time_output(recipient_meta, &fresh_ephemeral_sk);
    let commitment  = PedersenCommitment::commit(*amount, &fresh_blinding)?;
    // attach (stealth_out.one_time_pk, commitment, range_proof, encrypted_memo)
}
```

The transaction-level balance proof and aggregated range proof are produced once across all outputs (see §3 below). The full result is a `ConfidentialTransaction` that the SDK submits via the existing batch-round protocol — the operator's gRPC surface is the same one transparent VTXOs already use.

---

## 3. How range, balance, and nullifier proofs compose

Three proof types travel with every confidential transaction. They are independent primitives but they bind to the same transaction transcript so that no proof can be lifted out and replayed.

### 3.1 Range proof per output (ADR-0001)

Each Pedersen-committed amount must be provably in `[0, MAX_PROVABLE_AMOUNT]` where `MAX_PROVABLE_AMOUNT = 2^63 − 1` (Bitcoin's total supply ≈ 2^51, four orders of magnitude under the cap). Without a range proof, a malicious sender could commit to a wrap-around "negative" and balance it against a legitimate output, inflating supply.

The construction delegates to the audited Back-Maxwell rangeproofs in `secp256k1-zkp = 0.11`. ADR-0001 fixes the dependency and re-scopes the original Bulletproofs ask to "production-grade bounded-value range proofs on secp256k1" — Bulletproofs migration is tracked as follow-up `FU-BP`. The wire layout is opaque on purpose so `FU-BP` can land as an internal change.

API entry points (`crates/dark-confidential/src/range_proof.rs`):

- `RangeProof::prove(commitment, amount, blinding)` — single output.
- `RangeProof::prove_aggregated(commitments, amounts, blindings)` — N outputs in one framed blob. Saves `N - 3` bytes of framing vs. N singles; full log-size aggregation is gated on `FU-BP`.
- `verify_range(proof, commitment) -> bool`.
- `verify_range_aggregated(proof, commitments) -> bool`.

The verifier never reads amounts or blindings. Secret-data side-channels are confined to the prover.

### 3.2 Balance proof per transaction (#526)

Given inputs and outputs:

```text
Σ C_in − Σ C_out − commit(fee, 0) = commit(0, r_excess)
```

The amount legs cancel only when `Σ v_in − Σ v_out − fee = 0`, leaving `E = r_excess·H` of which the sender knows the discrete log. The balance proof is a textbook Schnorr signature over `H` (not `G`, so BIP-340 cannot be reused) attesting to that knowledge, plus a transcript binding the transaction so the signature is not portable to a different spend.

```text
prove:  k = H1(nonce_tag, r_excess, tx_hash)
        R = k·H
        e = H2(challenge_tag, R, E, tx_hash)  (mod n)
        s = k + e·r_excess                     (mod n)
verify: s·H == R + e·E
```

`H1` and `H2` are BIP-340-style tagged SHA-256 with distinct tags so the nonce derivation cannot collide with the challenge hash. Proof bytes are 65 (a 33-byte compressed `R` followed by a 32-byte canonical scalar `s`). See `crates/dark-confidential/src/balance_proof.rs`.

The balance proof binds the **whole** commitment set plus the fee plus the tx hash. Any post-hoc tamper of inputs, outputs, or fee flips the challenge `e` and the signature fails.

### 3.3 Nullifier per input (ADR-0002)

Each spent VTXO emits a nullifier that the operator stores in a global set. A second spend with the same nullifier is rejected — that is the double-spend prevention layer for confidential VTXOs.

```text
nullifier = HMAC-SHA256(
    key = secret_key_bytes,
    msg = "dark-confidential/nullifier" || 0x00 || version || vtxo_id_bytes,
)
```

`vtxo_id_bytes` is the canonical 36-byte encoding `32-byte txid || 4-byte big-endian vout`. Use `VtxoId::from(outpoint)` to produce it — never invent ad-hoc encodings. A different encoding silently changes which nullifier maps to which VTXO.

`version = 0x01` is hard-baked into the HMAC input, not the wire output. A future primitive change mints a new version byte but does not widen stored nullifier columns.

Nullifiers are deterministic given `(spend_secret, vtxo_id)`. If the spend secret never leaves the wallet, only the wallet can produce the nullifier — the operator cannot pre-compute it nor link two unspent VTXOs as belonging to the same wallet. (Once the VTXO is **spent**, the nullifier is published and is linkable forever; this is the "graph" in the threat model.)

### 3.4 How the three compose

The three proofs are independent but bind to the same `tx_hash`:

```text
                          ┌────────────────────────────────────┐
inputs  ─ nullifiers ─┐   │  tx_hash =                         │
                      ├──▶│    H(version || nullifiers ||      │
outputs ┐             │   │      output_commitments ||         │
        ├ commitments ┘   │      output_pubkeys || fee || ...) │
        ├ stealth pks ─── │                                    │
        └ memos       ─── └────────────────────────────────────┘
                                            │
              ┌─────────────────────────────┼─────────────────┐
              ▼                             ▼                 ▼
       Range proof per           Balance proof for      Operator-side
       output (binds            the whole tx (binds     nullifier set
       commitments)             tx_hash)                membership check
```

A doctored output amount flips its commitment, which flips the balance-proof challenge, which makes verification fail. A reused nullifier is rejected by the global set check before any cryptography runs. A swapped memo fails AEAD authentication on the recipient side. There is no failure mode where one proof "passes" and another "covers" for it.

---

## 4. Receive path: scan, decrypt, store

A confidential VTXO destined for your meta-address shows up in the operator's announcement stream as a `(round_id, vtxo_id, ephemeral_pubkey, encrypted_memo, ...)` record. To pick out yours and recover the cleartext `(amount, blinding)`:

1. **Subscribe** to `GetRoundAnnouncements` via `ArkClient::get_round_announcements` (wrapped behind the `AnnouncementSource` trait at `crates/dark-client/src/stealth_scan.rs`). The background `StealthScanner` already does this; for custom flows, drive the trait directly.
2. **Scan** each announcement against your `(scan_key, spend_pk)`. The current placeholder `scan_announcement` in `crates/dark-confidential/src/stealth/scan.rs` returns a match if and only if the announcement's `ephemeral_pubkey` would re-derive your one-time output pubkey under your scan secret — see #555 for the full ECDH scan.
3. **Decrypt** the memo. The sender's per-output ephemeral keypair is the input to ECDH, then HKDF-SHA256 to a 32-byte ChaCha20-Poly1305 key + 12-byte nonce, then AEAD-decrypt the 72-byte plaintext bound to `(version || ephemeral_pk || one_time_pk)` as associated data. See ADR-0003.
4. **Persist** the opening locally. The wallet stores `(vtxo_id, amount, blinding, one_time_sk)` per owned confidential VTXO. Encryption-at-rest is mandatory; see §5 below.

The `StealthScanner` exposes this loop with checkpointing (`CHECKPOINT_METADATA_KEY = "stealth_scan:checkpoint"`), backoff on transport errors, and pause/resume via `tokio_util::sync::CancellationToken`. Wallet restore from seed (`crates/dark-client/src/restore.rs`, issue #560) replays the same loop from genesis or from a `birthday_height` to recover all historical VTXOs without operator help.

---

## 5. What is encrypted at rest (#574)

The wallet stores plaintext openings for every confidential VTXO it owns. Persistence is encrypted at rest using the wallet's existing AES-256-GCM scheme with a key derived from the user's passphrase. Per #574, the on-disk record per owned confidential VTXO holds:

| Field | Sensitivity | Why it must be encrypted |
| --- | --- | --- |
| `vtxo_id` (txid + vout) | Public on-chain | Encrypted alongside the rest so that, even read together, no row leaks ownership |
| `amount` (u64 sats) | **Secret** | The whole point of confidentiality |
| `blinding` (32-byte scalar) | **Secret** | Disclosure of `blinding` opens `commitment` retroactively |
| `one_time_sk` (per-VTXO spend secret) | **Critical secret** | Disclosure is loss of funds |

Writes are atomic — no torn state on crash mid-write. A passphrase rotation re-encrypts the rows under a new KDF-derived key without re-running the round protocol. Migration from a wallet that previously held only transparent VTXOs preserves all transparent state and adds a `confidential_vtxos` namespace alongside it.

The acceptance test "encrypted at rest verified: on-disk bytes show no amounts" (#574) means: a hex dump of the wallet's confidential-store file must not contain the plaintext amount of any owned VTXO. This is verified by inserting a marker amount and grepping the file.

The viewing-key family (ADR-M6-DD) deliberately does **not** sit in the wallet store. A scoped viewing key is derived on demand from the master viewing key in memory, handed to the auditor, and dropped — the auditor's copy is what persists, on whatever medium the audit relationship requires.

---

## 6. Selective disclosure: opening one VTXO without opening the wallet

Three disclosure shapes ship in CV-M6 (ADR-M6-DD). All three are signed assertions about a single VTXO that a holder can ship to an auditor without giving up any other privacy.

### 6.1 Selective reveal (#565)

Open `(amount, blinding)` for one VTXO. Any third party can verify `commit(amount, blinding) == stored_commitment`. The proof is signed by the holder so recipients can attribute it.

```rust,ignore
use dark_confidential::{prove_selective_reveal, verify_selective_reveal,
                         DisclosedFields, SelectiveReveal};

let proof: SelectiveReveal = prove_selective_reveal(
    &vtxo,
    &opening,
    DisclosedFields::default()
        .with_exit_delay(144)
        .with_memo(b"audit-tag-Q3-2026".to_vec()),
    &spend_secret,
)?;

assert!(verify_selective_reveal(&proof, &commitment).is_ok());
```

Revealing one VTXO does **not** reveal related VTXOs or the graph. The proof binds to the VTXO's outpoint and owner pubkey via a tagged-hash transcript (DST `SELECTIVE_REVEAL_DST`). Wrong blinding fails verification cleanly.

### 6.2 Bounded-range proof (#566)

Prove the cleartext amount lies in `[lower, upper]` without revealing the exact value. Useful for "the amount was below threshold X" attestations under MiCA / Travel Rule.

```rust,ignore
use dark_confidential::disclosure::bounded_range::{prove_bounded_range,
                                                    verify_bounded_range};

let proof = prove_bounded_range(&value_commitment, amount, &blinding,
                                lower, upper)?;
assert!(verify_bounded_range(&proof, &value_commitment, lower, upper));
```

Note the convention split: bounded-range disclosure rides on `range_proof::ValueCommitment` (`amount·H + blinding·G`, ADR-0001), **not** on `commitment::PedersenCommitment` (`amount·G + blinding·H`). The two are not byte-compatible. Selective reveal binds to the standard commitment; bounded-range binds to `ValueCommitment`. See `crates/dark-confidential/src/disclosure/mod.rs` for the rationale.

### 6.3 Source-of-funds proof (#567)

Prove "this VTXO traces back N hops to a stated source set" without revealing intermediate hop amounts or recipients.

```rust,ignore
use dark_confidential::{prove_source_of_funds, verify_source_of_funds,
                         SourceLink, VtxoOutpoint};

let proof = prove_source_of_funds(
    &subject_vtxo,
    &opening_chain,    // [(VtxoOutpoint, PedersenOpening); >= 2]
    &allowed_roots,    // &[SourceLink]
    &signer_secrets,   // one per hop
)?;

verify_source_of_funds(&proof, &subject_vtxo, &allowed_roots)?;
```

The chain anchors at one of `allowed_roots` and terminates at the subject VTXO's outpoint. Each hop carries a Schnorr signature from its owner. Amounts at each hop are **not** revealed — only the graph shape and that each opening reconstructs a known commitment. See ADR-M6-DD §"Disclosure types" and `crates/dark-confidential/src/disclosure/source_of_funds.rs`.

### 6.4 Viewing key issuance (ADR-M6-DD)

Viewing keys grant ongoing post-hoc decryption authority for a bounded round window. The naive "hand over master `scan_sk`" approach is rejected by the ADR because it exposes the full meta-address history forever. Instead:

```text
   tweak    = HMAC-SHA512(master_secret_bytes,
                          SCOPE_DST || start_be8 || end_be8)[..32]
   k_scoped = (k_master + tweak) mod n
```

The scoped key decrypts only memos whose round id falls in `[start, end]`. The membership check in `RoundWindow::contains_ct` is constant-time over the bounds. See `crates/dark-confidential/src/viewing/`. ADR-M6-DD has the full threat model and the rationale for why scope lives in derivation, not in software policy.

---

## 7. CLI: `ark-cli` shortcuts

For day-to-day testing, `ark-cli` (in `crates/ark-cli/`) wraps the SDK with subcommands that exist today:

```bash
ark-cli stealth address                  # print wallet meta-address (TODO #553 follow-up)
ark-cli stealth encode <scan_pk> <spend_pk> --network mainnet
ark-cli stealth decode darks1...
ark-cli disclose --selective-reveal --vtxo <id> --out bundle.json
ark-cli verify --in bundle.json
```

`disclose` packs one or more disclosure types (selective reveal, bounded range, source-of-funds) into a compliance bundle. `verify` reads a bundle and exits non-zero if any contained proof fails to verify. See `crates/ark-cli/src/disclose.rs` and `crates/ark-cli/src/stealth.rs` for the option surface.

---

## 8. Operational checklist for integrators

Before shipping a wallet that supports confidential VTXOs:

- [ ] Verify the operator advertises mixed-round support (#541) — if not, confidential sends will not settle in the same round as transparent sends.
- [ ] Test wallet restore from seed against a regtest operator with > 1 round of historical VTXOs (#560).
- [ ] Confirm `birthday_height` propagation: a wallet that supplies a birthday must not silently re-scan from genesis.
- [ ] Verify encryption-at-rest with a marker-amount test: write a known plaintext amount to the store, hex-dump the on-disk file, assert the marker is absent (#574).
- [ ] Exercise the unilateral-exit confidential flow on a live regtest (`crate::confidential_exit::unilateral_exit_confidential`). The CLI surfaces progress as `LeafExitSigned → LeafExitBroadcast → CSV maturing → claimable`.
- [ ] If you support compliance disclosure, run the full `ark-cli disclose | ark-cli verify` round-trip and pin a fixture bundle in your tests.

---

## 9. ADR cross-reference

| ADR | What it pins | When you read it |
| --- | --- | --- |
| [ADR-0001](../adr/0001-secp256k1-zkp-integration.md) | `secp256k1-zkp` dependency, range-proof primitive, commitment convention, FU-BP roadmap | Working with range proofs or commitments |
| [ADR-0002](../adr/0002-nullifier-derivation.md) | Nullifier scheme, version byte, `vtxo_id` 36-byte encoding | Spending a VTXO; auditing double-spend defence |
| [ADR-0003](../adr/0003-confidential-memo-format.md) | Memo wire format, ECDH+HKDF+ChaCha20-Poly1305, 72-byte plaintext | Encrypting or decrypting memos |
| [ADR-0004](../adr/0004-confidential-fee-handling.md) | How fees compose with the balance proof | Fee programs, light-mode fee paths |
| [ADR-0005](../adr/0005-confidential-exit-script.md) | Confidential exit tapscript, witness layout `(amount, blinding, sig)` | Unilateral-exit flows |
| [ADR-M5-DD-stealth-derivation](../adr/m5-dd-stealth-derivation.md) | BIP-32 paths for scan / spend / view keys, multi-device flow | Wallet bring-up, restore, multi-device split |
| [ADR-M5-DD-announcement-pruning](../adr/m5-dd-announcement-pruning.md) | Operator's archival horizon, pruning policy | Restore from seed older than horizon |
| [ADR-M6-DD-disclosure-types](../adr/m6-dd-disclosure-types.md) | Disclosure shapes, transcript layout, attribution | Building auditor-facing flows |
| [ADR-M6-DD-compliance-bundle-format](../adr/m6-dd-compliance-bundle-format.md) | Wire format of the `disclose` / `verify` bundle | Persisting / shipping disclosure proofs |
| [ADR-M6-DD-viewing-key-scope](../adr/m6-dd-viewing-key-scope.md) | Viewing-key scoping by round window, scope tweak | Issuing a viewing key to an auditor |

---

## 10. Where to ask questions

- Bug reports: GitHub issues against `lobbyclawy/dark`. Tag `client` + `confidential-vtxos`.
- API surface questions: rustdoc at the canonical paths (`crates/dark-client/src/lib.rs`, `crates/dark-confidential/src/lib.rs`).
- Threat-model questions: see the [Confidential Threat Model](../security/confidential-threat-model.md).
- Migration from a transparent-only wallet: see the [migration guide](../migration/transparent-to-confidential.md).
