# Confidential VTXO Threat Model

- **Audience:** wallet authors, operators, security reviewers, and crypto-sign-off owners deciding whether the confidential design is fit for their deployment.
- **Scope:** what is hidden, from whom, under which assumptions; what is **not** hidden; consequences of compromise of each secret; adversary models for passive operator, malicious operator, compromised wallet, and compromised memo encryption key.
- **Status:** living document; ADRs cited are the controlling texts when this document is silent or ambiguous.
- **Companion documents:**
  - [Confidential Transactions: SDK Integrator Guide](../sdk/confidential-transactions.md)
  - [Migration: Transparent → Confidential](../migration/transparent-to-confidential.md)

---

## 1. Asset list

The objects we are protecting (or deliberately not protecting):

| Object | Sensitivity | Where it lives |
| --- | --- | --- |
| `amount` (per VTXO) | secret | wallet store (encrypted at rest); cleartext only inside the owner's process |
| `blinding` (per VTXO Pedersen scalar) | secret | wallet store (encrypted at rest); never leaves the owner's machine in cleartext |
| `one_time_sk` (per VTXO spend secret) | critical secret | wallet store (encrypted at rest); disclosure = loss of funds |
| `spend_sk` (master spend key) | critical secret | wallet keystore; disclosure = loss of funds |
| `scan_sk` (master scan key) | secret | scanning host (may be a different host than the spend host) |
| `view_sk` (master viewing key) | secret | wallet keystore; disclosure = retroactive decryption of all memos |
| Scoped viewing key (per audit window) | secret-to-auditor | auditor's host for the duration of the audit |
| `MetaAddress` (bech32m) | public | wherever recipients publish it |
| `nullifier` (per spent VTXO) | public after spend | global on-chain set |
| `commitment` (per VTXO) | public | round tree, on-chain anchor |
| `encrypted_memo` (per VTXO) | opaque ciphertext | round tree |
| `range_proof`, `balance_proof` | public | round tree |
| Tx existence and timing | public | operator logs, on-chain timing |

The cleartext quadruple `(vtxo_id, amount, blinding, one_time_sk)` is the wallet's confidential state, persisted under AES-256-GCM (#574).

---

## 2. What is hidden

Confidential VTXOs hide three pieces of data that are public on transparent VTXOs.

### 2.1 Amount

The on-chain commitment is `C = amount·G + blinding·H` (ADR-0001 convention). `H` is a deterministically-derived secp256k1 generator with no known discrete-log relationship to `G`. Recovering `amount` from `C` requires either:

- knowing `blinding` (so the verifier can subtract `blinding·H` and read off `amount·G`); or
- breaking discrete log on secp256k1.

Range proofs (ADR-0001) prove the committed amount lies in `[0, 2^63 − 1]` without revealing it. The verifier only sees the commitment and the proof — no amount, no blinding.

The aggregated view: an operator that holds the round tree and every commitment cannot read any individual amount. Pedersen commitments are perfectly hiding given a uniformly-random blinding factor; they leak nothing about the underlying value to a computationally-bounded adversary. The blinding-factor reuse caveat is in §6.1 below.

### 2.2 Recipient identity

Every confidential output is locked to a **one-time public key** that the sender derives per-output via ECDH against the recipient's published meta-address. The output pubkey on-chain has no statistical relationship to the meta-address — recovering the meta-address from a one-time pubkey requires the recipient's `scan_sk`.

The recipient runs the scanning loop (#558) to identify their own outputs. An observer without `scan_sk` sees a stream of unrelated one-time pubkeys.

This is the "stealth" half of the privacy guarantee. ADR-M5-DD covers the BIP-32 derivation, the read-only / spending-authority key separation, and the multi-device flow (mobile scanner + cold-storage signer).

### 2.3 Graph linkability beyond what nullifiers reveal

The nullifier set is a one-way function of the spend secret and the VTXO id. Two unspent VTXOs owned by the same wallet have **no** publicly-derivable link — an operator that observes only commitments, one-time pubkeys, and memos cannot tell that two VTXOs belong to the same wallet without scanning them, which it cannot do without `scan_sk`.

Once a VTXO is **spent**, its nullifier is published. The spend graph (which inputs feed which outputs) becomes public. This is deliberate: it is the double-spend defence layer. See §3.3 for the consequences.

---

## 3. What is NOT hidden

Confidentiality is bounded. Several public facts remain visible to the operator and to anyone with on-chain access. Integrators MUST internalise these before claiming any privacy property to end users.

### 3.1 Transaction existence

The operator sees that a confidential transaction occurred: a set of nullifiers was consumed, a set of commitments was created, a fee was paid, range and balance proofs were posted, and memos were forwarded.

There is no "private mempool". An observer with operator-level access knows a confidential transaction happened and at what time.

### 3.2 Transaction timing

The operator timestamps every transaction it batches. Round cadence is public. A user who sends a payment immediately after receiving one creates a timing correlation that the operator can record even though it cannot read either amount.

Tor at the transport layer hides the user's network identity from the operator (and the operator's network identity from the user) but does **not** hide the timing of the events themselves.

### 3.3 Spend graph (after spend)

When a VTXO is spent, its nullifier is published. If the same wallet later spends another VTXO that pays the same recipient, the recipient's incoming nullifiers form a graph that links the two spends as having a common destination — even though the amounts and the recipient's identity stay hidden.

In particular, the graph reveals:

- That two outputs went to the same one-time pubkey if (somehow) two outputs reused a one-time pubkey. The protocol does not reuse one-time pubkeys, so this is hypothetical, but bears stating.
- That a chain of spends exists: `nullifier_A` was consumed in tx-1, which produced `commitment_X`, which was consumed (after some time) producing `nullifier_X`, etc. The graph shape is public; amounts and recipients along it are not (modulo stealth scanning).

Source-of-funds proofs (#567) deliberately use this linkable-graph property: a holder can prove "this VTXO traces back N hops to a stated source" without revealing intermediate hop amounts. The graph is already public; the proof just signs over a specific path through it.

### 3.4 Fee amounts

Fees are committed in the clear (`commit(fee, 0)` per ADR-0004). They feed into the balance proof identity. Fee amounts are public per transaction.

This is intentional: fee programs (CEL-based) need to evaluate fees at the operator and at validation, both of which are public-data computations. ADR-0004 covers the rationale and the alternatives considered.

### 3.5 Operator-known metadata

The operator knows, per its own logs:

- The IP address that submitted each transaction (mitigated by Tor).
- The `MetaAddress` that any user published to its operator-side address book, if it operates such a book. (The protocol does not require the operator to know the meta-address — the user is free to share it out-of-band.)
- The macaroon / auth token associated with each request, where macaroon auth is in use.
- The session ids of long-lived gRPC streams.

A "passive" operator (§4.1) records this metadata. A "malicious" operator (§4.2) selectively withholds, reorders, or fabricates announcements to manipulate the user's view.

### 3.6 Round-tree leaf type

`LeafV1` (transparent) and `LeafV2` (confidential) carry a distinct domain-separation tag in their leaf-hash preimage (#540). An on-chain observer can tell which leaves are transparent and which are confidential. They cannot tell the *amount* of a confidential leaf, only that it is confidential.

This is unavoidable given the parity gate (the transparent preimage must remain byte-identical to Go `arkd`'s preimage, so the confidential preimage cannot disguise itself as transparent). Per #541's anti-segregation rationale, mixed rounds prevent the operator-level signal "this user is using the private feature", but a chain observer still sees confidential-vs-transparent at the leaf level.

### 3.7 Exit timing and exit script structure

The unilateral-exit confidential flow (ADR-0005) broadcasts a tapscript leaf transaction that an on-chain observer can identify as an Ark exit. The CSV delay and the witness layout are public. The committed amount in the witness (`(amount, blinding, signature)`) becomes public when the exit broadcasts — this is "exit leakage": the confidentiality of a VTXO is partially revoked when it unilaterally exits.

Cooperative exits (`collaborative_exit`) do not have this leakage — the operator coordinates the exit and only the on-chain destination amount is visible, not the prior VTXO amount.

---

## 4. Adversary models

Four canonical adversaries. The model determines what the wallet must defend against and what guarantees the operator can promise.

### 4.1 Passive operator

**Capability:** sees every gRPC request, every round-tree leaf, every nullifier, every commitment, every memo ciphertext. Logs everything. Does not deviate from protocol.

**Defended:**
- Cannot read VTXO amounts (Pedersen + range proofs).
- Cannot read VTXO recipients (stealth one-time pubkeys, ECDH-derived).
- Cannot decrypt memos (AEAD with recipient-only key, ADR-0003).
- Cannot link two unspent VTXOs of the same wallet (no public ownership signal).
- Cannot forge nullifiers without the spend secret.

**Not defended:**
- Sees all transaction existence and timing (§3.1, §3.2).
- Sees the spend graph after each spend (§3.3).
- Sees fees in cleartext (§3.4).
- Sees IP addresses and auth metadata (§3.5).
- Sees confidential-vs-transparent leaf type (§3.6).
- Can correlate sessions across time using IP, macaroon, or stream ids.

**Mitigations under user control:**
- Tor for transport-layer privacy.
- Macaroon rotation (operator-side feature; ask before relying on it).
- Multiple meta-addresses per logical identity (the wallet decides the policy; the protocol does not constrain it).

### 4.2 Malicious operator

**Capability:** everything the passive operator can do, plus:
- Withhold or reorder announcements selectively per user.
- Refuse specific transactions.
- Refuse to include specific spends in rounds.
- Lie about the round-tree state to specific users.
- Mount denial-of-service against specific users.

**Defended:**
- Cannot steal funds. Confidential VTXOs are locked to one-time pubkeys that only the holder of the corresponding spend secret can authorise.
- Cannot inflate supply. The balance proof prevents net positive issuance; range proofs prevent wrap-around negatives.
- Cannot replay or graft memos onto wrong VTXOs (memo AEAD binds to the one-time pubkey, ADR-0003).
- Cannot tamper with proofs without invalidating them (every proof binds to the tx hash).
- Cannot bypass the unilateral-exit path. A user who detects operator misbehaviour can broadcast their round-tree leaf and exit on-chain via ADR-0005.

**Not defended:**
- Can DoS specific users (refuse their transactions, withhold announcements). Mitigation: detect the failure, switch operator, exit unilaterally if needed.
- Can selectively reorder transaction inclusion within a round, which can leak information in correlation with timing data.
- Can lie to one user about what rounds exist; users should cross-check the on-chain anchor against an independent Bitcoin node.

**Mitigations under user control:**
- Run an independent Bitcoin node to verify on-chain anchors.
- Use the unilateral-exit flow when the operator misbehaves.
- Maintain hot/cold wallet split so the always-online scanning host cannot lose funds even if the operator coordinates with an attacker that compromises the scanning host.

### 4.3 Compromised wallet (full-host compromise)

**Capability:** attacker reads the wallet store, including the AES-256-GCM key (because they have host access and the user has unlocked the wallet at some point during the compromise window).

**Outcome:**
- Loss of funds (attacker has `spend_sk` and per-VTXO `one_time_sk`).
- Retroactive de-anonymisation (attacker has `scan_sk` and `view_sk`, can decrypt past memos).
- Future de-anonymisation (attacker has `scan_sk`, can scan the announcement stream and decrypt new memos until the user rotates the meta-address).

**Mitigations:**
- The `Zeroize` discipline on `ScanKey`, `SpendKey`, `ViewingKey`, `ScopedViewingKey` reduces the window during which secrets sit in process memory unmasked. It does not protect against an attacker who reads memory while the wallet is unlocked.
- Multi-device key separation (ADR-M5-DD): a compromise of the always-online scanning host (which holds `scan_sk`) does not leak `spend_sk` if the spend host is offline. The attacker can de-anonymise but not steal.
- Hardware wallet integration for `spend_sk` is a roadmap item; signed-on-device flow keeps `spend_sk` off the host even when the host is compromised.

The compromise of `view_sk` is conceptually similar to compromise of `scan_sk` — the holder can decrypt past memos. ADR-M6-DD discusses why scoped viewing keys (`ScopedViewingKey`) reduce the blast radius vs. master `view_sk`.

### 4.4 Compromised memo encryption key (per-VTXO)

**Capability:** attacker recovers the AEAD key for a specific memo, by some means — side-channel, badly-seeded ephemeral keypair on the sender side, etc.

**Outcome (single memo):**
- Attacker reads `(amount, blinding, one_time_spend_tag)` for that one VTXO.
- Attacker can spend that one VTXO if they can also forge the recipient's signature on the leaf script (which requires `spend_sk`, which they do not have from the memo alone).
- Attacker cannot link this VTXO to other VTXOs of the same recipient — the memo carries only that VTXO's data.

**Outcome (recipient's `scan_sk` compromised):**
- Attacker can decrypt every past, present, and future memo addressed to the recipient's meta-address.
- This is the §4.3 retroactive de-anonymisation outcome.

**Outcome (sender's per-output ephemeral private key compromised, post-facto):**
- Attacker can decrypt that one memo (the sender's ephemeral key + the recipient's `scan_pk` reproduce the ECDH shared secret).
- Bound to that single output — ephemeral keypairs are fresh per output (ADR-0003).

The memo design pins three forward-secrecy-ish properties:
- Per-output ephemeral keypair: a leaked ephemeral key opens only one memo.
- Cross-version safety: a v1 memo cannot be re-tagged as v2 without breaking authenticity (ADR-0003).
- AEAD binding to the one-time pubkey: an attacker cannot graft a valid memo onto a different output.

---

## 5. Compromised viewing key consequences (ADR-M6-DD scope)

The viewing key family has its own threat model because it grants ongoing read access to the recipient's memo stream. ADR-M6-DD-viewing-key-scope is the controlling text; this section is the integrator-facing summary.

### 5.1 Master `view_sk`

A holder of the master viewing key can decrypt **every** confidential memo addressed to the wallet's meta-address — past, present, and future, until the user rotates the meta-address (which costs them their published identifier and re-key with every counterparty).

This is incompatible with institutional audit relationships where the auditor needs visibility into a bounded period only. ADR-M6-DD rejects "share `scan_sk`" and "share `view_sk` master" as the disclosure mechanism for exactly this reason.

### 5.2 Scoped viewing key (`ScopedViewingKey`)

A scoped viewing key is bound to an inclusive `RoundWindow { start_round, end_round }`. The scope is enforced via a deterministic, scope-bound tweak applied to the master scalar:

```text
tweak    = HMAC-SHA512(master_secret_bytes,
                       SCOPE_DST || start_be8 || end_be8)[..32]
k_scoped = (k_master + tweak) mod n
```

Because the tweak is keyed by the master secret, knowing a scoped key does not let the holder recover the master — inverting the tweak requires the master itself. A scoped key compromise is bounded to its window:

| Compromise | Past memos in scope | Past memos out of scope | Future memos in scope | Future memos out of scope |
| --- | --- | --- | --- | --- |
| Scoped `view_sk` for `[100, 200]` | readable | not readable | readable | not readable |
| Master `view_sk` | readable | readable | readable | readable |

Decryption attempts are gated by `ScopedViewingKey::may_view`, which is **constant-time over the scope bounds** (`RoundWindow::contains_ct` reduces the ≤-comparison to a sign-bit extraction on a 128-bit subtraction, no `if`/`match` on secret-derived intermediates). The audit anchor is `expose_secret()` — every disclosure site is reachable via `grep expose_secret`.

The viewing-scope ADR (#561, controlling text ADR-M6-DD-viewing-key-scope) is still being decided in detail; the current encoding is `[start_round, end_round]`. A future scope encoding (epoch- or time-based) ships under a new version byte without changing the public API of `dark_confidential::viewing`. The wire encoding lives behind `RoundWindow` so migration is a single-file change.

### 5.3 Issuance hygiene

When issuing a scoped viewing key:

- Derive it just-in-time from `view_sk.scope_to(window)`. Do not persist the scoped key on the issuing wallet — the auditor's copy is the persistent form.
- Use the narrowest window that satisfies the audit. A 24-hour audit covering a single transaction does not need a 90-day window.
- Treat the channel to the auditor as adversarial: a TLS-pinned channel, a sealed envelope, a hardware token. Compromise of the channel = compromise of the key for that scope.
- After the audit ends, the scoped key cannot be revoked (it is just a scalar). The recipient can rotate their master, which invalidates all future scoped keys derived from the old master. They cannot un-disclose past memos.

The companion `m6-dd-disclosure-types` ADR covers the **one-shot** disclosure primitives (selective reveal, bounded range, source of funds). Those do not give ongoing decryption authority and are the preferred disclosure shape when the audit only needs a single-fact attestation.

---

## 6. Cryptographic-discipline failure modes

The following are not adversary models but operational failure modes. They are listed here because misuse breaks the privacy guarantee even against a passive operator.

### 6.1 Blinding-factor reuse

If two distinct VTXOs commit to amounts under the same blinding scalar, the difference of their commitments collapses to `(v1 − v2)·G`. An observer who guesses `v1` can read off `v2 − v1`. Reusing a blinding factor across distinct amounts therefore leaks the delta.

Mitigation: derive each output's blinding factor deterministically from `(seed, vtxo_index)` via a tagged KDF. The wallet implements this; `create_confidential_tx` (#572) wires the determinism in. Hand-rolled clients must follow the same discipline.

`PedersenCommitment` rejects the zero scalar at construction (`scalar must be non-zero and within curve order`). It does not police uniqueness — that is the wallet's job.

### 6.2 Nonce reuse in the range proof

Each range proof draws a fresh nonce from the OS CSPRNG. Reusing a nonce across proofs that commit to the same value leaks the blinding factor; across different values it leaks the delta. The range-proof module documents this at the top of `crates/dark-confidential/src/range_proof.rs`.

Issue #529 pins a deterministic, protocol-scoped KDF that will replace CSPRNG sampling in a future version. Until then, integrators must not stub `OsRng` with a deterministic source.

### 6.3 Nonce reuse in the balance proof

The balance-proof nonce `k` is derived deterministically from `(r_excess, tx_hash)` via a domain-separated tagged hash (`H1`). Re-signing the same `(r_excess, tx_hash)` produces identical bytes — a feature for audit reproducibility. Re-signing the same `r_excess` against a *different* `tx_hash` is safe (messages differ → challenges differ → s values differ → no key leak). The danger is re-using `r_excess = 0`, which collapses `E` to the identity and would let any `s` verify; the prover rejects this at sign time.

### 6.4 Cross-protocol transcript reuse

Every cryptographic transcript carries a domain-separation tag. Examples: `NULLIFIER_DST = "dark-confidential/nullifier"`, `PEDERSEN_H_DST = "dark-confidential/pedersen-h/v1"`, `SELECTIVE_REVEAL_DST`, `SOURCE_OF_FUNDS_DST`, `BOUNDED_RANGE_TRANSCRIPT_DST`, `SCOPE_DST = "dark-confidential viewing scope v1"`. Reusing a tag across protocols can collide hashes; minting a new tag per protocol is mandatory for any future primitive.

### 6.5 Recipient pubkey substitution

Memo AEAD binds to `(version || ephemeral_pubkey || one_time_pubkey)` as associated data. An operator that swaps the on-chain one-time pubkey but leaves the memo intact breaks AEAD authentication on the recipient side. Decryption fails cleanly — no silent corruption.

Recipients who ignore an AEAD failure ("retry with different keys") undermine this. The scanner is required to treat AEAD failure as "not addressed to me" and continue scanning.

### 6.6 Replay across networks

Meta-addresses carry their network in the bech32m HRP. Cross-network decode is rejected at parse time. A mainnet meta-address will not silently decode on testnet, and vice versa. Wallets that paste user-supplied strings into `MetaAddress::from_bech32m` get this defence for free.

The same discipline applies to `StealthNetwork` round trips: every encode reflects the network, every decode validates it.

---

## 7. What Tor adds, and what it does not

Tor at the transport layer hides:

- The user's IP address from the operator.
- The operator's IP address from the user.
- The fact that any specific user is talking to any specific operator (for a sufficiently large Tor user base — the standard caveat).

Tor does **not** hide:

- Transaction existence (the operator still sees the gRPC request).
- Transaction timing (Tor adds latency but not cover traffic).
- Per-session correlation (long-lived gRPC streams over Tor are still long-lived gRPC streams).
- Operator-side metadata such as macaroons, session ids, or auth tokens that the user supplies regardless of transport.

Wallets that claim "private payments" must clarify that Tor is a network-layer mitigation that complements protocol-level confidentiality, not a substitute. A Tor-less wallet still gets full Pedersen / stealth / nullifier privacy from the operator, but the operator learns the IP address of every transaction.

---

## 8. Limits of selective disclosure

Selective disclosure (ADR-M6-DD-disclosure-types) is opt-in, signed, and bounded to a specific VTXO. The integrator-facing limits:

- **Selective reveal** (#565) opens `(amount, blinding)` for one VTXO. It does not reveal anything about related VTXOs or the holder's other balances.
- **Bounded range** (#566) proves the amount lies in `[lower, upper]`. Tighter bounds leak more (the verifier can narrow the bracket); broader bounds leak less. Bound choice is policy.
- **Source of funds** (#567) reveals the graph shape from a stated source to the subject VTXO. The amounts at each hop are not revealed; the VTXO ids are. An auditor that knows the source set learns the graph shape — that is the point of the proof — but cannot derive amounts or recipient identities at the intermediate hops.
- **Scoped viewing key** (ADR-M6-DD-viewing-key-scope) gives ongoing decryption authority within its window. It is the heaviest disclosure primitive and the one whose scope semantics are most load-bearing. Prefer one-shot proofs whenever possible.

A user who issues both a scoped viewing key and a source-of-funds proof for the same VTXO has disclosed strictly more than either primitive in isolation. There is no mechanism to "redact" past disclosures.

---

## 9. Crypto sign-off checklist

The acceptance criterion at #577 says "security model reviewed by whoever owns crypto sign-off". The reviewer is asked to confirm:

- [ ] The asset list (§1) is complete.
- [ ] What-is-hidden (§2) and what-is-not (§3) match the protocol's actual behaviour against `crates/dark-confidential/src/` and the cited ADRs.
- [ ] Adversary models (§4) are exhaustive for the deployment in question; if the deployment includes a compromised-Bitcoin-node model or compromised-clock model, those are ADR'd separately.
- [ ] Viewing-key blast-radius (§5) matches ADR-M6-DD-viewing-key-scope.
- [ ] Operational failure modes (§6) are covered by the wallet's tests.
- [ ] Tor scope (§7) is reflected in user-facing privacy claims.
- [ ] Selective-disclosure limits (§8) are reflected in the wallet's disclosure UX.

If any item fails, file an issue against `lobbyclawy/dark` with the `confidential-vtxos` + `security-critical` labels.

---

## 10. ADR cross-reference

| ADR | Threat-model relevance |
| --- | --- |
| [ADR-0001](../adr/0001-secp256k1-zkp-integration.md) | Pedersen `H` derivation, range-proof construction, FU-BP roadmap, primitive constraints |
| [ADR-0002](../adr/0002-nullifier-derivation.md) | Nullifier scheme, version byte, double-spend defence |
| [ADR-0003](../adr/0003-confidential-memo-format.md) | Memo encryption, AEAD binding, cross-version safety |
| [ADR-0004](../adr/0004-confidential-fee-handling.md) | Fee-cleartext rationale, balance-proof feed-in |
| [ADR-0005](../adr/0005-confidential-exit-script.md) | Exit witness, exit leakage, unilateral-exit shape |
| [ADR-M5-DD-stealth-derivation](../adr/m5-dd-stealth-derivation.md) | Read-only / spending-authority key separation, multi-device flow |
| [ADR-M5-DD-announcement-pruning](../adr/m5-dd-announcement-pruning.md) | Operator's archival horizon, restore-from-seed limits |
| [ADR-M6-DD-disclosure-types](../adr/m6-dd-disclosure-types.md) | One-shot disclosure primitives, transcript binding |
| [ADR-M6-DD-compliance-bundle-format](../adr/m6-dd-compliance-bundle-format.md) | Bundle wire format, attribution |
| [ADR-M6-DD-viewing-key-scope](../adr/m6-dd-viewing-key-scope.md) | Viewing-key scope, scoped-key blast-radius, constant-time membership |

---

## 11. Open questions

These are tracked but not yet ADR'd. The threat-model implications change when they resolve.

- **Hardware-wallet integration for `spend_sk`.** The blast radius of §4.3 (compromised wallet) shrinks substantially with HW signing, but the integration is not yet specified.
- **Padding / cover traffic.** No protocol-level cover traffic exists today. A user who wants to defeat timing correlation against a passive operator must run their own padding scheme.
- **Long-running gRPC stream correlation.** Sessions are correlated by stream id and macaroon. A reconnect / rotate cadence is operator policy; the protocol does not enforce one.
- **Mempool-level operator-vs-Bitcoin-node split.** A future variant might separate the round-coordinating operator from the on-chain anchoring service. The threat model would gain a fifth adversary; this guide will be updated when that lands.

The list is non-exhaustive. File issues for additional vectors.
