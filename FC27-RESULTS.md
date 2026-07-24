# FC'27 measurement results

Results for the seven-task brief closing the measurement gaps the FC 2027
paper declares as caveats. One section per task: status, reproduction
commands, measured numbers, and - for T2/T3/T7 - an explicit **paper
delta** listing every number that differs from what the paper currently
states.

**Run environment.** Apple M3 Max (14 cores, 36 GB RAM), macOS 26,
rustc 1.97.0 (paper pins 1.95.0), criterion `--quick`. arkd comparisons
pin **v0.7.0** (`fcb9f21ef69836e8ddadc2d070deb0c5be139336`), the commit
the paper cites. Same machine *class* as the paper; the rustc minor-version
delta is the only toolchain difference and is called out where it matters.

| Task | What | Status |
|------|------|--------|
| T1 | Keep the anonymous link alive | **Partial** - link live and current; expiry not owner-readable from here; anonymity leak found in mirror content |
| T2 | Instrument Arkade Delegation (A1-A6) | **Done** - harness + report; 4 of 6 measured, 1 refuted, 1 needs Fulmine |
| T3 | Instrumented `slot_attest` on regtest | **Done** - measured 189 vB (vs 201 analytical) |
| T4 | Equivocation-evidence demo binary | **Done** - runnable demo + CI + tests; 400 B pair |
| T5 | Threshold FROST branch | **Blocked** - no FROST branch exists anywhere; written finding |
| T6 | Re-verify arkd pinning vs latest | **Done** - both cited symbols unchanged at v0.9.15 |
| T7 | Reproduce headline benchmarks | **Done** - all within ~5%, none over the 10% flag |

---

## T1 - Anonymous link

**Status: Partial.** The mirror resolves and serves current code, but its
expiry is not readable without owner access, and its file *content* leaks
author identity.

### Link resolves - yes

```bash
curl -s "https://anonymous.4open.science/api/repo/dark-CCD5/options"
curl -s "https://anonymous.4open.science/api/repo/dark-CCD5/files/"   # lists the tree
```

- `options` returns HTTP 200 with
  `"lastUpdateDate":"2026-05-02T21:56:00.801Z"`. That timestamp matches
  the head commit of `origin/main` (`42f60f8`, 2026-05-02), so the mirror
  is serving the current code, submodules included
  (`"hasSubmodules":true`).
- The file listing includes the PSAR/VON tree (`BENCHMARKS.md`,
  `crates/`, `benches/`, etc.).

### Expiry - not verifiable from here (action needed by the owner)

4open.science exposes the expiration date only to the repo owner. The
public `options` payload carries `"isOwner":false` and **no**
`expirationDate` field, and the `/conference` endpoints return
`not_connected` / `not_found`. There is no unauthenticated way to read
whether the link survives past February 2027.

**Action:** the owner must open the repo on
`https://anonymous.4open.science`, read the expiry on the dashboard, and
extend it past the conference dates (Feb 2027) if it falls short. If it
cannot be extended, re-anonymize and report the new URL (the paper cites
it at `sec:eval`, line 805 of `psar.tex`).

### Anonymity leak in mirror content (important)

4open.science blinds paths and strips git metadata but does **not** scrub
file *contents*. The following identity leaks are live on the cited
mirror:

- `README.md` `## Authors` section: real names + emails ("Lobby
  (lobbyclawy@gmail.com)", "Andrea Carotti (ac.carotti@gmail.com)").
- `README.md` badges and clone/docker URLs: the `lobbyclawy` GitHub
  handle and `ghcr.io/lobbyclawy/dark`.
- `authors = ["Lobby <...>", "Andrea Carotti <...>"]` in three
  `Cargo.toml` files (`dark-psar`, `dark-von`, `dark-von-musig2`) and
  others.

These defeat author-blinding for a double-blind submission. Fix at
re-export time via Anonymous GitHub's term-removal list (add the names,
emails, and `lobbyclawy`), or scrub the `Authors` section and `authors`
fields before anonymizing. This was **not** changed in the origin repo
here - the origin is intentionally non-anonymous, so the scrub belongs to
the anonymization step, not to `main`.

---

## T2 - Arkade Delegation instrumentation (A1-A6)

**Status: Done.** Reproducible harness under
`scripts/arkade-delegation/` (`main.go`, `measure.sh`, `README.md`),
pinning `ark-lib` to arkd v0.7.0. Four assumptions measured, one refuted
by code + measurement, one requires the external Fulmine delegate.

**Headline finding.** arkd v0.7.0 has **no native `delegate` primitive**
(`git grep -i delegat` over the whole tree returns nothing). The
"delegate" of A2/A5/A6 is necessarily an external, Fulmine-style always-on
signer that holds the user's VTXO keys and drives the ordinary client
RPCs. So A2/A3/A4 are measurable on real arkd (the RPC + on-chain cost);
A5 is an architectural statement about a component outside arkd; A6 is
that external component's private storage and cannot be measured without
Fulmine.

### Reproduce

```bash
# Offline: Tapscript construction + witness sizing (A1, A3 delta)
cd scripts/arkade-delegation && go run . script

# Live: boot arkd v0.7.0 on Nigiri, board + renew, capture intent store
nigiri start
scripts/arkade-delegation/measure.sh --out arkade-delegation-results.md

# Size a captured intent row by hand (A3)
go run . intentsize -proof-file proof.txt -message-file message.txt
```

The live path was exercised: ASP wallet bootstrapped, a VTXO boarded and
renewed twice on Nigiri regtest, and arkd's `intent`/`round`/`tx` tables
captured from `sqlite.db`.

### Per-assumption result

| # | Assumption (paper) | Verdict | Measured / evidence |
|---|--------------------|---------|---------------------|
| A1 | Renewal Tapscript is CLTV-gated 3-of-3 `CLTVMultisigClosure` (user, delegate, ASP), `pkg/ark-lib/script/closure.go` | **Confirmed** | Built with pinned ark-lib: **108 B** script (vs 68 B for the standard 2-of-2). Type is on the forfeit/renewal path (`vtxo_script.go` `ForfeitClosures`, `offchain/tx.go:122`, validated in `service.go:506`). |
| A2 | Each renewal needs a per-batch `RegisterIntent` by the settling party | **Confirmed** (registration); forfeit sub-claim **Refuted** | Measured: exactly **1 intent per round per participant** across 2 ended rounds. But the parenthetical "forfeit tx is pre-signed by the user at boarding with SIGHASH_ALL\|ANYONECANPAY" is wrong: the forfeit is built per-round against that round's connector (`builder.go:474`) and signed **SIGHASH_DEFAULT** (`tree/forfeit_tx.go:46`); it cannot be pre-signed at boarding because the connector outpoint does not exist yet. |
| A3 | Per-renewal authorisation wire size is 64 B | **Confirmed for the signature**, with a large payload refinement | The authorisation **signature** is 64 B (SIGHASH_DEFAULT), confirmed in the captured witness. But the actual per-renewal **RegisterIntent payload measured at 1093 B** (483 B proof tx, base64 to 644 chars, + 440-char message + protobuf framing). The BIP-322 proof-of-funds signature is **65 B** (64 + 1 sighash-flag byte, SIGHASH_ALL). |
| A4 | Renewal folds into the next batch commitment, no own on-chain tx | **Confirmed** | Measured: **1 `commitment` tx per round**; arkd builds one commitment for all intents (`service.go:1523`) and broadcasts it once (`service.go:1864`). Forfeit txs are stored, not broadcast, unless a user later cheats. |
| A5 | The delegate (not the user) is the always-on party | **Refuted as native / holds externally** | No `delegate` primitive in arkd v0.7.0. The always-on party arkd knows is the operator/signer. A delegate that settles for an offline user is external (Fulmine); the assumption is true only of that external component. |
| A6 | The delegate stores ~400 B per VTXO per active epoch | **Unmeasurable without Fulmine** | arkd persists only small per-VTXO state (outpoint + amount + output pubkey + flags; `vtxo` table), no tapscript tree, no forfeit tx. A minimal external-delegate handle is ~360-500 B (tapscript tree dominates), so ~400 B is a plausible order-of-magnitude - but the full serialized per-epoch intent is ~1 KB (measured 1093 B). Exact figure needs the Fulmine implementation. |

### Paper delta (T2)

| Where | Claim in paper | This run | Note |
|-------|----------------|----------|------|
| App eval, A2 parenthetical | "forfeit tx is pre-signed by the user at boarding with SIGHASH_ALL\|ANYONECANPAY" | Forfeit is built per-round vs the round connector and signed SIGHASH_DEFAULT; not pre-signable at boarding | Refuted by ark-lib code (`forfeit_tx.go:46`, `builder.go:474`). Recommend rewording A2. |
| App eval, A3; Table 1 "per-renewal marginal" | per-renewal authorisation 64 B | Signature **64 B** (holds); full per-renewal RegisterIntent payload **~1093 B**; proof-of-funds sig **65 B** | If "64 B" denotes just the added signature, it stands. If it denotes the renewal's wire cost, the measured payload is ~17x larger. Clarify which the table means. |
| Table 1, "Peak off-chain state per cohort" | ~400 KB at delegate (400 B x 1000 VTXOs) | Minimal handle ~400 B plausible, but full serialized intent ~1 KB/VTXO | Flag, not a confirmed correction - needs Fulmine to measure the delegate's real retained state. |
| App eval, A1 | 3-of-3 CLTV multisig | Confirmed; script is 108 B, +105 B witness (+26.25 vB) per renewed input vs 2-of-2 | Supports A1; adds a concrete per-input size the paper can cite if useful. |

---

## T3 - Instrumented `slot_attest` on regtest

**Status: Done.** The existing `scripts/psar-onchain.sh` was wired to a
real broadcast and run against Nigiri. One fix was needed: the regtest
test did not print the `slot_attest_txid:` line the script greps for; it
now does (`crates/dark-psar/tests/e2e_psar_regtest.rs`).

### Reproduce

```bash
nigiri start
scripts/psar-onchain.sh --out psar-onchain-results.md
```

Broadcasts the real `slot_attest` OP_RETURN (68-byte payload: 4-byte
`PSAR` magic + 64-byte BIP-340 sig), mines it, and reads canonical
weight/vbytes back from bitcoind.

### Measured vs analytical

| Metric | Analytical (paper) | Measured (regtest) | Delta |
|--------|--------------------|--------------------|-------|
| vbytes | 201 | **189** | -6% |
| raw bytes (size) | 281 | **270** | -4% |
| weight units | 803 | **753** | -6% |
| OP_RETURN payload | 68 B | 68 B | 0 |

Breakdown of the confirmed tx: 0 B scriptSig input, 104 B witness
(single P2WPKH key-spend), 92 B outputs (68 B OP_RETURN script + P2WPKH
change).

**Why measured < analytical.** The broadcast is a real 1-input / 2-output
transaction: one segwit-v0 P2WPKH funding input (witness = 1 sig + 1
pubkey) and a P2WPKH change output. The analytical 201 vB was a
conservative upper bound; the actual layout is slightly lighter. The
figure is input-type dependent - a legacy or Taproot funding input would
move it - so the measured 189 vB is specific to a P2WPKH-funded
publication.

### Paper delta (T3)

| Where | Claim in paper | This run |
|-------|----------------|----------|
| `sec:eval:throughput` (~line 842) and App eval "Storage and on-chain composition" | "~201 vbytes (281 raw bytes, 803 weight units)", labelled analytical | Measured on regtest: **189 vbytes, 270 raw bytes, 753 WU** (P2WPKH-funded). The paper can replace "analytical" with "measured 189 vB on regtest", or keep 201 vB as a conservative bound and cite the measurement. |

---

## T4 - Equivocation-evidence demo binary

**Status: Done.** Added `crates/dark-psar/src/bin/equivocation-demo.rs`,
wired into CI, plus a security-boundary test that pins the paper's
"test (iv)".

### Reproduce

```bash
cargo run -p dark-psar --bin equivocation-demo      # one command, clean checkout
cargo test -p dark-psar --test equivocation_evidence
```

The demo runs a real cohort setup (`asp_board`), simulates a misbehaving
operator signing a second schedule root for the same `cohort_id`,
verifies the pair with **exactly two BIP-340 checks and no other state**,
and prints the serialized evidence.

### Measured evidence size

| Object | Size |
|--------|------|
| One `SlotAttest` (136 B unsigned payload + 64 B BIP-340 sig) | **200 B** |
| Equivocation pair (both attestations) | **400 B** |
| Incremental, if the legitimate attestation is already public | **200 B** |

The paper says the evidence is "~200 bytes" (`psar.tex` line 551). That
matches the **incremental** cost (the second, conflicting attestation) and
the size of each attestation; the standalone pair is 400 B. No paper
change needed - the ~200 B figure is correct as the marginal evidence
size.

### CI + docs

- `.github/workflows/ci.yml`: the `test` job runs the demo binary on
  every build (`cargo run -p dark-psar --all-features --bin
  equivocation-demo`).
- `crates/dark-psar/tests/equivocation_evidence.rs`: boundary (iv) -
  pair verifies with two BIP-340 checks, wire size pinned at 400 B,
  tamper detection, same-root negative control. Runs in the workspace
  test job.
- `README.md`: new "Equivocation-Evidence Demo (PSAR)" section
  (anonymization-safe wording).

Note: this fills a real gap. Before this, the paper's "test (iv)" was
described in the source but had **no** corresponding test that signs two
conflicting attestations and verifies both - only VON-level ECVRF
equivocation and the documented-but-untested attestation-level property
existed. `equivocation_evidence.rs` now exercises it directly.

---

## T5 - Threshold FROST branch

**Status: Blocked.** There is no FROST / threshold branch to rebase,
compile, or benchmark - anywhere.

### What was searched

- **Local + remote branches:** all 22 GitHub branches on `lobbyclawy/dark`
  and every local branch. The only VON-adjacent non-main branch is
  `revision/von-construction-rebuild`, which is Phase 6 + the schedule-root
  commit - no threshold code.
- **Full history:** `git log --all -S` for `frost`, `FROST`, `dkg`,
  `ThresholdVrf`, `trusted_dealer` - zero hits. No `rust-frost` /
  `frost-core` in any `Cargo.toml` or `Cargo.lock` on any ref.
- **Stashes:** none contain FROST.
- **Working tree:** the only multiparty scheme present is 2-of-2 MuSig2
  (ASP + user). Threshold appears only as prose: `SECURITY.md` ("future"),
  ADR-0007 (aspirational "threshold-Schnorr could reuse the wrapper").

### Finding

The paper describes a "`rust-frost` for the threshold variant"
(`psar.tex` line 808) and a "threshold extension ... feature-branch
prototype" (line 1039). **That code does not exist in the repository.**
The threshold material is theory only: the VON-FROST construction and
`Thm frost-composition` in appendix `app:frost`.

**What blocks integration:** the implementation has to be *written* first
(FROST DKG + FROST-Schnorr threshold signing + a threshold VRF), then it
can be rebased, feature-flagged, and benchmarked. There is nothing to
promote to "measured prototype" yet. No benchmarks were fabricated for
non-existent code, and no paper claim was changed.

**Recommendation:** either (a) keep the paper's honest "feature-branch
prototype, not a contribution" framing, or (b) if promotion before FC is
desired, scope a minimal `dark-von-frost` crate (trusted-dealer keygen is
enough for a `(k,n)` benchmark) - that is net-new implementation work, not
a rebase.

---

## T6 - arkd pinning vs latest release

**Status: Done.** Latest arkd release is **v0.9.15** (2026-07-20). Both
symbols the paper cites still exist and behave as described.

### Reproduce

```bash
cd vendor/arkd
git show v0.9.15:pkg/ark-lib/script/closure.go | grep -n CLTVMultisigClosure
git show v0.9.15:internal/core/application/service.go | grep -n 'func (s \*service) RegisterIntent'
```

### Findings

| Symbol | v0.7.0 (pinned) | v0.9.15 (latest) | Verdict |
|--------|-----------------|------------------|---------|
| `CLTVMultisigClosure` (`pkg/ark-lib/script/closure.go`) | struct at :394, registered "CLTV Multisig" closure | struct at :408, registered :45 | **Unchanged in substance.** Still a CLTV-gated multisig on the forfeit/renewal path. Minor internal churn only: `common` -> `arklib` package rename for the `Locktime` type, and CLTV scriptnum-decoding fixes (#665, #687). |
| `RegisterIntent` (renewal path) | RPC handler `service.go:799`; proof verified via `bip322` `proof.Verify` (`service.go:940`) | RPC handler `service.go:1499`; proof verified via `intent.Verify` (`pkg/ark-lib/intent/proof.go:57`) | **Present and unchanged as the renewal entry point.** The proof verification was refactored into a dedicated `intent.Verify` by v0.9.x; at v0.7.0 it was `bip322` `proof.Verify`. |

Note on the brief's "`intent.Verify`": that symbol is **v0.9.x-only** -
there is no `pkg/ark-lib/intent` package at v0.7.0. The paper's own text
cites `CLTVMultisigClosure` and `RegisterIntent` (not `intent.Verify`), and
both are stable v0.7.0 -> v0.9.15.

**Conclusion:** a "still true as of v0.9.15" annotation is supportable for
the two cited symbols. The paper stays pinned to v0.7.0 either way.

---

## T7 - Reproduce headline benchmarks

**Status: Done.** All headline numbers reproduce within ~5%; nothing
exceeds the 10% flag threshold.

**Important run note.** An initial pass ran the benchmarks *while a Docker
image was building on the same machine* and showed `process_epoch` inflated
by ~48%. That was CPU contention, not a regression. The numbers below are a
**clean** re-run on an otherwise-idle machine; they match the paper. Always
run these benches with nothing else on the cores.

### Reproduce

```bash
cargo bench -p dark-psar --bench boarding -- --quick        # user_board, N in {4,12,50}
cargo bench -p dark-psar --bench epoch    -- --quick        # process_epoch, K in {100,1000}
BENCH_LONG=1 cargo bench -p dark-psar --bench epoch -- long  # K=10000
scripts/psar-scaling.sh --include-stretch                    # end-to-end wall-clock + storage
```

### user_board vs horizon N (K=2)

| N | Paper | This run (median) | Delta |
|---|-------|-------------------|-------|
| 4 | 1.66 ms | **1.663 ms** | +0.2% |
| 12 (lead) | 4.75 ms | **4.862 ms** | +2.4% |
| 50 | 19.80 ms | **20.147 ms** | +1.8% |

### process_epoch vs cohort K (N=12)

| K | Paper | This run (median) | Delta |
|---|-------|-------------------|-------|
| 100 | 22.9 ms | **23.504 ms** | +2.6% |
| 1,000 (lead) | 226.8 ms | **234.19 ms** | +3.3% |
| 10,000 (`BENCH_LONG`) | 2.29 s | **2.388 s** | +4.3% |

Per-user at the lead row: **234 us/user** (paper 227 us), i.e. **~4,270
renewals/s** (paper 4,410). Within noise.

### Storage formula at the lead row (K=1000, N=12)

`186K + 98KN + 292N + 180` = **1,365,684 bytes = 1.37 MB** (decimal MB, as
the paper uses) = 1.30 MiB. Matches the paper's 1.37 MB exactly.

### VON-MuSig2 primitives (supporting)

| Bench | This run (median) |
|-------|-------------------|
| `aggregate/2of2` | 20.44 us |
| `partial_sign/operator` | 44.77 us |
| `partial_sign_participant_horizon/12` | 2.74 ms |

### Paper delta (T7)

**None material.** Every headline number reproduces within ~5%, all under
the paper's own 10% flag. The small positive bias (boarding/epoch ~+2-4%)
is consistent with the rustc 1.97.0 vs 1.95.0 toolchain delta and normal
`--quick` variance. No claim needs changing. The storage lead figure is
exact.

---

## Summary of recommended paper actions

Nothing here was written back to the paper (out of scope). For the
`psar-paper` integration afterwards:

1. **T1 (urgent, anonymity):** verify/extend the 4open.science expiry
   past Feb 2027, and scrub author identity from mirror content at
   re-export.
2. **T2:** reword A2 (forfeit is per-round SIGHASH_DEFAULT, not
   boarding-time SIGHASH_ALL|ANYONECANPAY); clarify whether A3's "64 B" is
   the signature (holds) or the renewal wire cost (~1093 B measured);
   treat the ~400 KB delegate-storage cell as needing Fulmine to confirm.
3. **T3:** the ~201 vB attestation is now measured at 189 vB on regtest -
   upgrade the label from "analytical" or cite the measurement.
4. **T4:** ~200 B evidence confirmed (200 B/attestation, 400 B pair);
   "test (iv)" now actually exists as a test.
5. **T5:** no threshold code exists; keep the honest "not a contribution"
   framing unless net-new implementation is scoped.
6. **T6:** add "still true as of arkd v0.9.15" for `CLTVMultisigClosure`
   and `RegisterIntent` if desired; stay pinned to v0.7.0.
7. **T7:** headline numbers reproduce within ~5%; no changes needed.
