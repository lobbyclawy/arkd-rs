# Migration: Transparent VTXOs → Confidential VTXOs

- **Audience:** maintainers of existing wallet integrations against the transparent Ark protocol who want to opt their users into Confidential VTXOs without breaking spendability of existing balances.
- **Scope:** what changes for the wallet, what does **not** change, the new SDK surface, and the backwards-compatibility guarantees the protocol gives you.
- **Companion documents:**
  - [Confidential Transactions: SDK Integrator Guide](../sdk/confidential-transactions.md)
  - [Confidential Threat Model](../security/confidential-threat-model.md)

---

## 1. TL;DR

- Existing transparent VTXOs **stay valid forever**. They remain spendable at face value with no re-batching, no migration round, and no operator coordination required (#541, #520 parity gate).
- A wallet opts in to confidential sends per call (or globally, via a new `default_confidential` flag described in §4 below). Receiving confidentially additionally requires the wallet to publish a stealth meta-address; until it does, senders cannot reach it confidentially.
- Mixed transparent/confidential rounds are first-class. There is no "confidential round" vs. "transparent round" — a single round batches both, and the round-tree root is byte-identical to today's Go-`arkd` root for any transparent-only leaf set (#540, the Go-parity gate).
- Wallet-store schema gains a `confidential_vtxos` namespace for cleartext openings, encrypted at rest under the existing AES-256-GCM scheme (#574). The `transparent_vtxos` namespace is unchanged.

The migration is **additive**. No transparent-side schema changes, no consensus changes, no Bitcoin script changes. If you do nothing, your wallet keeps working exactly as it does today.

---

## 2. What does NOT change

This section is the load-bearing one. Internalise it before reading anything else.

### 2.1 Existing transparent VTXOs remain spendable

A VTXO created before the confidential rollout is a `LeafV1` in the round tree. Its leaf hash preimage is byte-identical to the Go `arkd` preimage. The Rust `dark-core` round-tree builder dispatches on variant:

```text
tree_leaf_hash(vtxo: &Vtxo) -> [u8; 32] {
    match vtxo {
        Transparent(t)  => leaf_v1_hash(t),  // byte-identical to Go arkd
        Confidential(c) => leaf_v2_hash(c),  // distinct domain prefix
    }
}
```

Per #540 acceptance criteria, the Rust root for any transparent-only leaf set must equal the Go `arkd` root byte-for-byte, with a regression fixture committed. A user who upgrades their wallet but never sends confidentially sees zero change.

### 2.2 Forfeit / exit / unilateral-exit semantics

Forfeit transactions and exit semantics for transparent VTXOs are unchanged. The vendored Go `arkd` E2E suite passes unchanged on transparent-only rounds — that is a non-negotiable acceptance criterion of #540 and #541. If your integration relies on the Go test vectors, they continue to apply.

The unilateral-exit path for confidential VTXOs is the new code path (`crates/dark-client/src/confidential_exit.rs`, ADR-0005). The witness format is different — `(amount, blinding, signature)` for confidential vs. just `(signature)` for transparent — but the trigger flow (round-tree leaf broadcast, CSV maturing, claim) is the same shape.

### 2.3 gRPC surface

The operator's gRPC surface (`ArkService`, `IndexerService`, `WalletService`, `SignerManagerService`) is **additive**:

- `GetRoundAnnouncements` is a new stream. Existing clients that do not subscribe see no behaviour change.
- `VerifyComplianceProof` is a new endpoint (#569). Existing clients never need to call it.
- Existing methods (`GetInfo`, `ListVtxos`, `Settle`, `Send`, `RedeemNotes`, `CollaborativeExit`, etc.) are unchanged in signature and semantics on transparent VTXOs.

### 2.4 Wallet derivation for transparent funds

The transparent wallet derivation path (`m/86'/{coin}'/0'/{0,1}/{idx}`) is unchanged. `SingleKeyWallet::generate` / `from_wif` / `from_secret_bytes` continue to work and produce the same on-chain addresses they did before. The stealth scan / spend / view keys live under disjoint BIP-32 regions per ADR-M5-DD; deriving them does not perturb the transparent path.

---

## 3. What does change for the wallet

### 3.1 New keys to derive at wallet bring-up

A confidential-aware wallet derives three additional keys per account from the same BIP-39 seed:

| Key | Purpose | Visibility | Derivation path | Type |
| --- | --- | --- | --- | --- |
| `scan_sk` | detect inbound VTXOs | read-only credential | `scan_path(account_index)` (ADR-M5-DD) | `dark_confidential::stealth::ScanKey` |
| `spend_sk` | authorise spend | full spending authority | `spend_path(account_index)` (ADR-M5-DD) | `dark_confidential::stealth::SpendKey` |
| `view_sk` | decrypt past memos under a scope | read-only audit credential | `view_path(account_index)` (ADR-M5-DD) | `dark_confidential::viewing::ViewingKey` |

All three are wrapped types with `Zeroize` on drop and no `Copy` / `Clone` / `Debug`. Bytes leave the wrappers only via `expose_secret()` — that name is the audit anchor.

```rust,ignore
use dark_confidential::stealth::{MetaAddress, StealthNetwork, StealthSecrets};
use dark_confidential::viewing::ViewingKey;

let (meta, StealthSecrets { scan_key, spend_key }) =
    MetaAddress::from_seed(&seed, account_index, StealthNetwork::Mainnet)?;

let view_key = ViewingKey::from_seed(&seed, account_index)?;
```

The published `MetaAddress` (bech32m `darks1...`) replaces the bare 33-byte compressed pubkey as the recipient identifier for confidential sends. The bare pubkey is still valid for transparent sends; see §4 below.

### 3.2 New on-disk state to persist (#574)

For each owned confidential VTXO, the wallet persists a row in the `confidential_vtxos` namespace:

```text
(vtxo_id, amount, blinding, one_time_sk)
```

`vtxo_id` is the canonical 36-byte `txid || vout` per ADR-0002. `amount` and `blinding` are the Pedersen opening — required to spend, and required to keep encrypted at rest. `one_time_sk` is the per-VTXO spend secret derived from `(spend_sk, ephemeral_pk, scan_sk)` ECDH.

Encryption-at-rest reuses the wallet's existing AES-256-GCM scheme (passphrase-derived KDF). Writes are atomic — no torn state on crash mid-write. The `transparent_vtxos` namespace is unchanged.

> Acceptance criterion from #574: a hex dump of the wallet store must not contain the plaintext amount of any owned VTXO. Verify this with a marker-amount test (`amount = 0xCAFE_BABE_DEAD_BEEF`) before shipping.

### 3.3 New background task: stealth scanner (#558)

To detect inbound confidential VTXOs the wallet runs a background task that streams `GetRoundAnnouncements`, scans each against `(scan_sk, spend_pk)`, decrypts the memo on a match, and persists the opening:

```rust,ignore
use dark_client::stealth_scan::{StealthScanner, DEFAULT_POLL_INTERVAL};
use tokio_util::sync::CancellationToken;

let cancel = CancellationToken::new();
let scanner_task = StealthScanner::new(scan_sk, spend_pk, source, store, cancel.clone())
    .with_poll_interval(DEFAULT_POLL_INTERVAL)
    .start();
```

Checkpointing under `CHECKPOINT_METADATA_KEY = "stealth_scan:checkpoint"` lets the scanner resume after restart without re-scanning. Backoff and reconnect on transport errors are built in. See `crates/dark-client/src/stealth_scan.rs` and ADR-M5-DD.

A wallet that does not run the scanner cannot detect inbound confidential VTXOs. Transparent inbound payments still surface via `ListVtxos` exactly as before.

### 3.4 Restore from seed with stealth re-scan (#560)

`restore_from_seed` now walks the operator's historical announcements to rediscover every confidential VTXO. It reuses the same scanner page-handling code so live scanning and restore stay byte-consistent.

```rust,ignore
use dark_client::restore::{restore_from_seed, RestoreConfig};

let summary = restore_from_seed(
    &seed,
    RestoreConfig {
        operator_url: "http://localhost:50051".into(),
        birthday_height: Some(523_000),  // optional; skips ancient rounds
        ..Default::default()
    },
).await?;

println!("recovered {} confidential VTXOs", summary.recovered_confidential);
```

`birthday_height` is an opt-in optimisation. Without it, `restore_from_seed` walks the full archival horizon (operator-defined, see ADR-M5-DD-announcement-pruning) and surfaces a typed `BirthdayBeforeArchivalHorizon` error if the requested birthday is older than the operator's pruning window.

A wallet upgrading from transparent-only to confidential restore should re-run the restore once after introducing stealth keys; otherwise no historical confidential VTXOs are visible until a fresh sync replays the announcement stream.

---

## 4. API differences

### 4.1 Recipient identifier: `MetaAddress` vs. raw pubkey

| Direction | Today (transparent) | After migration (confidential opt-in) |
| --- | --- | --- |
| Wire encoding | bare 33-byte compressed pubkey hex, optionally prefixed `ark:` | bech32m `darks1...` / `tdarks1...` / `rdarks1...` (mainnet/testnet/regtest) |
| Type in SDK | `String` (pubkey hex) | `dark_confidential::stealth::MetaAddress` |
| Detection | operator returns VTXOs by pubkey lookup | recipient scans announcement stream (§3.3) |
| Versioning | none | explicit version byte inside the bech32m payload (currently `0x01`) |

The transparent identifier (raw pubkey hex / `ark:<hex>`) continues to work for transparent sends. A wallet that publishes only its meta-address can still receive transparent payments at its pubkey, and a wallet that publishes only its pubkey can still receive transparent payments. The two namespaces coexist; the wallet decides per outgoing payment which to use.

### 4.2 `default_confidential` flag

The SDK gains a wallet-level boolean that controls the default for outgoing payments:

- `default_confidential = false` (default): `send_offchain(to_address, amount)` continues to send transparently. To send confidentially, call the confidential send path explicitly with a `MetaAddress`.
- `default_confidential = true`: `send_offchain` upgrades to confidential when the destination is a `MetaAddress`. If the destination is a bare pubkey, the SDK either falls back to transparent or rejects with a typed error — wallets choose which behaviour at construction time.

Wallets that want a hard "confidential only" stance set the flag, set the fallback to "reject", and refuse to construct sends to bare pubkeys.

This flag is **policy**, not protocol. The operator does not see it. It only changes which SDK send path the wallet selects.

### 4.3 New SDK methods

| Method | Crate path | Status |
| --- | --- | --- |
| `MetaAddress::from_seed` | `dark_confidential::stealth` | shipped |
| `MetaAddress::from_bech32m` / `to_bech32m` | `dark_confidential::stealth` | shipped |
| `ViewingKey::from_seed` / `scope_to` | `dark_confidential::viewing` | shipped |
| `derive_nullifier` | `dark_confidential::nullifier` | shipped |
| `PedersenCommitment::commit` | `dark_confidential::commitment` | shipped |
| `RangeProof::prove` / `prove_aggregated` | `dark_confidential::range_proof` | shipped |
| `prove_balance` / `verify_balance` | `dark_confidential::balance_proof` | shipped |
| `prove_selective_reveal` / `verify_selective_reveal` | `dark_confidential::disclosure::selective_reveal` | shipped (#565) |
| `prove_bounded_range` / `verify_bounded_range` | `dark_confidential::disclosure::bounded_range` | shipped (#566) |
| `prove_source_of_funds` / `verify_source_of_funds` | `dark_confidential::disclosure::source_of_funds` | shipped (#567) |
| `StealthScanner::start` / `restore_from_seed` | `dark_client::stealth_scan` / `dark_client::restore` | shipped (#558, #560) |
| `unilateral_exit_confidential` | `dark_client::confidential_exit` | shipped (#548) |
| `create_confidential_tx` / `send_confidential` | `dark_client` | pending #572 (CV-M7) |

The `create_confidential_tx` builder in #572 is the integration point most wallets will reach for. Until it lands on `main`, integrators can compose the primitive APIs directly — see §2 of the [SDK guide](../sdk/confidential-transactions.md). The signatures of the primitives are stable; #572 only adds a builder around them.

### 4.4 New CLI subcommands

`ark-cli` (`crates/ark-cli/`) gains:

| Subcommand | Purpose |
| --- | --- |
| `stealth address` | print wallet's meta-address (TODO #553 follow-up: needs key management wiring) |
| `stealth encode <scan_pk> <spend_pk> [--network ...]` | encode a meta-address from explicit pubkeys |
| `stealth decode darks1...` | decode a meta-address, print scan/spend hex |
| `disclose` (with `--selective-reveal`, `--lower N --upper M`, or `--source-of-funds <root>`) | assemble a compliance bundle |
| `verify --in bundle.json` | verify every proof in a bundle, exit non-zero if any fails |

Existing transparent subcommands (`info`, `round`, `vtxo`, `board`, `send`, `receive`, `list-vtxos`, `exit`) are unchanged.

### 4.5 New error variants

`ConfidentialError` (in `dark-confidential`) is a separate error type from `ClientError` so callers can match on confidential-specific failures without flattening them into the existing transparent error space:

```rust,ignore
pub enum ConfidentialError {
    InvalidEncoding(&'static str),
    InvalidInput(&'static str),
    Stealth(&'static str),
    Viewing(&'static str),
    // ... see crates/dark-confidential/src/errors.rs
}
```

`DisclosureError` (`dark_confidential::disclosure::DisclosureError`) is a further-narrowed flavour for selective-disclosure-specific failures (`OpeningMismatch`, `AmountOutOfRange`, `RangeNotCertified`, `TranscriptMismatch`, ...).

`RestoreError` adds `BirthdayBeforeArchivalHorizon` for the case where the operator's archival horizon has advanced past the requested birthday.

---

## 5. Backwards-compatibility guarantees

These are the contracts the protocol commits to. Each is the controlling text for its scope; if you find a conflict between code and this section, file an issue.

### 5.1 Transparent VTXOs are spendable forever

There is no flag day. There is no expiry. A transparent VTXO created today can be spent or settled into a round 10 years from now. The round tree continues to dispatch on variant; `LeafV1` continues to use the byte-identical Go `arkd` preimage; the operator continues to honour transparent forfeit signatures. The acceptance criterion at #541 ("vendored Go `arkd` E2E suite passes unchanged on a transparent-only round") is enforced in CI and will not be relaxed.

### 5.2 No required rotation, no migration round

A wallet that holds only transparent VTXOs never has to "migrate". It can consolidate, send, and exit them without ever publishing a meta-address or running a stealth scanner.

A wallet that wants to start using confidential VTXOs does so by publishing a meta-address and starting a scanner — without changing any of its existing transparent VTXOs.

### 5.3 Mixed rounds (#541)

Round batching accepts transparent and confidential transactions in a single batch. The operator's batching logic does not segregate by variant — segregating would leak which users are "using the private feature". Per-round counts are emitted as `round_confidential_tx_count` / `round_transparent_tx_count` metrics without leaking owner info.

### 5.4 Mainnet / testnet / regtest separation

Stealth meta-addresses carry their network in the bech32m HRP (`darks` / `tdarks` / `rdarks`). Cross-network decode is rejected at parse time. A mainnet meta-address cannot be silently consumed on testnet, and vice versa. See `crates/dark-confidential/src/stealth/network.rs`.

Existing transparent network handling (taproot HRP, bitcoin `Network` discriminator) is unchanged.

### 5.5 Versioning

Two versioning surfaces matter for migration:

- **Meta-address payload:** version byte sits inside the bech32m payload. Decoder rejects unknown versions explicitly. Adding `v2` reuses the same HRP. (`META_ADDRESS_VERSION_V1 = 0x01`.)
- **Nullifier construction:** version byte sits inside the HMAC input, not on the wire output. Migrating to a new primitive mints a new version byte but does not widen stored nullifier columns. (`NULLIFIER_VERSION_V1 = 0x01`.)

Memo encryption and selective-disclosure transcripts each carry their own DST (domain-separation tag) that includes a version. ADR-0003 and ADR-M6-DD-disclosure-types are the controlling texts.

### 5.6 Wallet seed phrases do not change

A BIP-39 mnemonic that backs a transparent-only wallet today is the same mnemonic that backs the confidential-aware wallet after upgrade. The transparent path keys are unchanged. The stealth keys derive from the same seed under disjoint BIP-32 regions. No re-mnemonic, no re-seed.

---

## 6. Step-by-step migration recipe

A typical wallet upgrade looks like this. Each step is independently shippable.

1. **Add the dependency.** Pull `dark-confidential` into the wallet's crate graph alongside `dark-client`.
2. **Derive stealth keys at wallet open.** On every wallet load, derive `(MetaAddress, StealthSecrets)` and a `ViewingKey` from the existing seed. Persist nothing new yet.
3. **Add a new wallet-store namespace.** Introduce `confidential_vtxos` alongside `transparent_vtxos`. Do not touch `transparent_vtxos`. Encrypt-at-rest under the same passphrase-derived AES-256-GCM key (#574).
4. **Run the stealth scanner.** Spawn `StealthScanner` against the operator. Wallets without an always-online scanner can run it on wallet open and on user-initiated refresh; this is fine for low-frequency wallets, but high-volume wallets should keep it persistent.
5. **Add a confidential-receive UI.** Display the bech32m meta-address as a QR code alongside the existing transparent address. Allow the user to share either or both.
6. **Add a confidential-send code path.** Compose the primitive APIs (or wait for #572 and call `create_confidential_tx`). Default the `default_confidential` flag to `false` until you have run the round-trip on regtest.
7. **Integrate the unilateral-exit confidential flow.** `unilateral_exit_confidential` covers the new witness format. The existing transparent unilateral-exit code path remains for `LeafV1` VTXOs.
8. **(Optional) Wire selective disclosure.** If your users will need compliance disclosure (institutional / exchange flows), surface `disclose` and `verify` from `ark-cli` or call the disclosure APIs directly.
9. **Run regtest E2E.** A round with mixed transparent + confidential VTXOs must settle. Verify against the operator's mixed-round acceptance test (#541).
10. **Flip `default_confidential = true`** for users who opt in. Ship.

---

## 7. FAQ

**Q: Do my users need to rotate their keys?**

No. The same BIP-39 seed produces the same transparent keys it did before, plus a disjoint set of stealth and viewing keys. Old VTXOs remain spendable under the old keys.

**Q: Can a transparent wallet pay a confidential meta-address?**

Yes — the *sender* uses the same `dark-confidential` primitives whether or not the sender's own funds are confidential. A wallet that holds only transparent VTXOs can spend them as confidential outputs. The reverse also holds: a wallet that holds confidential VTXOs can spend them to a transparent recipient (the spend authorises the input nullifier; the output side is where confidentiality lives).

**Q: What happens if the operator does not support confidential rounds?**

Confidential sends fail with a typed error. Transparent sends continue to work. The wallet should detect operator capability via `GetInfo` and gate the confidential UI accordingly.

**Q: What if the user loses their passphrase?**

Same as today: the seed phrase recovers the wallet. Re-running `restore_from_seed` (now with stealth re-scan) recovers all VTXOs, transparent and confidential. The wallet store on disk is opaque without the passphrase, but the seed is the source of truth.

**Q: Can I keep using `SingleKeyWallet` for everything?**

`SingleKeyWallet` covers the transparent path. For confidential, you also need `MetaAddress` + `StealthSecrets` + `ViewingKey`. They sit alongside `SingleKeyWallet`, not replacing it.

**Q: Are there any consensus changes?**

No. Confidential VTXOs ride on existing Bitcoin script. ADR-0005 covers the confidential exit script (a tapscript leaf, not a soft fork). The on-chain anchor transaction is unchanged.

---

## 8. ADR cross-reference

| ADR | Why it matters for migration |
| --- | --- |
| [ADR-0001](../adr/0001-secp256k1-zkp-integration.md) | New crate dependency (`secp256k1-zkp = 0.11`). Pulled in by `dark-confidential`. |
| [ADR-0002](../adr/0002-nullifier-derivation.md) | Nullifier wire format. Wallet must encode `vtxo_id` as 36 bytes (`txid || vout BE`). |
| [ADR-0003](../adr/0003-confidential-memo-format.md) | Memo encryption scheme. Wallet decrypts via the recipient's scan key. |
| [ADR-0004](../adr/0004-confidential-fee-handling.md) | Fee programs and how fees feed into the balance proof. Read before changing fee policy. |
| [ADR-0005](../adr/0005-confidential-exit-script.md) | Unilateral-exit witness format. Required for `unilateral_exit_confidential`. |
| [ADR-M5-DD-stealth-derivation](../adr/m5-dd-stealth-derivation.md) | BIP-32 paths for scan / spend / view keys. Required to derive new keys correctly. |
| [ADR-M5-DD-announcement-pruning](../adr/m5-dd-announcement-pruning.md) | Operator's archival horizon. Determines max viable `birthday_height`. |
| [ADR-M6-DD-disclosure-types](../adr/m6-dd-disclosure-types.md) | Disclosure surface for compliance flows. |
| [ADR-M6-DD-compliance-bundle-format](../adr/m6-dd-compliance-bundle-format.md) | Wire format of `disclose` / `verify` bundles. |
| [ADR-M6-DD-viewing-key-scope](../adr/m6-dd-viewing-key-scope.md) | Viewing-key scoping. Required for time-bounded audit relationships. |

---

## 9. Where to file follow-ups

If your integration runs into a sharp edge that the protocol could smooth, file an issue against `lobbyclawy/dark` with the `client` + `confidential-vtxos` + `migration-feedback` labels. The migration acceptance criterion at #577 includes "at least one external integrator spot-reviews the migration guide" — feedback shapes the next revision.
