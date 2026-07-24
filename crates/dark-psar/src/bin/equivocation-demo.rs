//! Equivocation-evidence demo.
//!
//! The central accountability object of PSAR: two BIP-340-signed slot
//! attestations sharing a `cohort_id` but committing to different
//! schedule roots. Anyone holding the pair and the operator's
//! attestation key can verify operator equivocation with exactly two
//! BIP-340 signature checks and no other state.
//!
//! The demo:
//!
//! 1. runs a real cohort setup ([`asp_board`]) and produces the
//!    legitimate slot attestation;
//! 2. simulates a misbehaving operator running a second setup for the
//!    same `cohort_id` (a conflicting schedule shown to a different
//!    audience) and signing its schedule root;
//! 3. verifies the pair with exactly two BIP-340 verifications;
//! 4. prints the serialized evidence and its exact byte size.
//!
//! Run from a clean checkout:
//!
//! ```text
//! cargo run -p dark-psar --bin equivocation-demo
//! ```
//!
//! Exits non-zero if any step fails. The same boundary is pinned in CI
//! by `tests/equivocation_evidence.rs`.

use std::process::ExitCode;

use rand::rngs::StdRng;
use rand::SeedableRng;
use secp256k1::{Keypair, Parity, Secp256k1, SecretKey, XOnlyPublicKey};

use dark_psar::{
    asp_board, compute_schedule_root, CohortMember, HibernationHorizon, SlotAttest,
    SlotAttestUnsigned,
};
use dark_von_musig2::setup::Setup;

/// Cohort size for the demo run. Small so the demo finishes in
/// milliseconds; the equivocation property is size-independent.
const K: u32 = 4;

/// Hibernation horizon (epochs of pre-signed renewals).
const N: u32 = 3;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("equivocation-demo: FAILED: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let secp = Secp256k1::new();
    let mut rng = StdRng::seed_from_u64(0x5eed);

    // ── 1. Real cohort setup → legitimate attestation ────────────────
    let asp_kp = even_parity_keypair(&secp, 0x07);
    let pk_attest = asp_kp.x_only_public_key().0;

    let members_and_keys: Vec<(CohortMember, Keypair)> = (0..K)
        .map(|i| {
            let kp = even_parity_keypair(&secp, 0x10 + i as u8);
            let member = CohortMember {
                user_id: [0x40 + i as u8; 32],
                pk_user: kp.x_only_public_key().0.serialize(),
                slot_index: i,
            };
            (member, kp)
        })
        .collect();

    let cohort_id = [0xc0u8; 32];
    let setup_id_a = [0xa1u8; 32];
    let horizon = HibernationHorizon::new(N, N).map_err(|e| e.to_string())?;

    let active = asp_board(
        &asp_kp,
        cohort_id,
        members_and_keys,
        horizon,
        setup_id_a,
        None,
        &mut rng,
    )
    .map_err(|e| e.to_string())?;
    let attest_a = active.attest;

    println!("── 1. cohort setup (K={K}, N={N}) ──────────────────────────────");
    println!("cohort_id           : {}", hex::encode(cohort_id));
    println!(
        "pk_attest (x-only)  : {}",
        hex::encode(pk_attest.serialize())
    );
    println!(
        "legit schedule_root : {}",
        hex::encode(attest_a.unsigned.schedule_root)
    );

    // ── 2. Misbehaving operator: second root, same cohort_id ─────────
    // `Setup::run` is deterministic in (sk, setup_id, n), so showing a
    // second audience a different schedule means running setup under a
    // fresh setup_id. The crime is signing a second schedule root for
    // the same cohort_id.
    let setup_id_b = [0xb2u8; 32];
    let asp_sk = SecretKey::from_keypair(&asp_kp);
    let (schedule_b, _retained_b) =
        Setup::run(&asp_sk, &setup_id_b, N).map_err(|e| e.to_string())?;
    let root_b = compute_schedule_root(&cohort_id, &schedule_b).map_err(|e| e.to_string())?;

    let unsigned_b = SlotAttestUnsigned {
        setup_id: setup_id_b,
        schedule_root: root_b.0,
        ..attest_a.unsigned
    };
    let attest_b = unsigned_b.sign(&secp, &asp_kp);

    println!("── 2. equivocating attestation (same cohort_id) ───────────────");
    println!(
        "second schedule_root: {}",
        hex::encode(attest_b.unsigned.schedule_root)
    );

    // ── 3. Verify the pair: exactly two BIP-340 checks ───────────────
    verify_pair(&attest_a, &attest_b, &pk_attest)?;
    println!("── 3. pair verified ───────────────────────────────────────────");
    println!("BIP-340 checks used : 2 (one per attestation)");
    println!("state needed        : the two attestations + pk_attest, nothing else");

    // ── 4. Serialized evidence ───────────────────────────────────────
    let mut evidence = Vec::with_capacity(2 * SlotAttest::SIZE);
    evidence.extend_from_slice(&attest_a.to_bytes());
    evidence.extend_from_slice(&attest_b.to_bytes());

    println!("── 4. serialized evidence ─────────────────────────────────────");
    println!("evidence (hex)      : {}", hex::encode(&evidence));
    println!(
        "attestation size    : {} B each ({} B unsigned payload + 64 B BIP-340 sig)",
        SlotAttest::SIZE,
        SlotAttestUnsigned::SIZE
    );
    println!(
        "evidence pair size  : {} B total ({} B if the legitimate attestation is already public)",
        evidence.len(),
        SlotAttest::SIZE
    );
    println!("equivocation-demo: OK");
    Ok(())
}

/// Equivocation-pair check: same `cohort_id`, different
/// `schedule_root`, and exactly two BIP-340 verifications against
/// `pk_attest`. No state beyond the two attestations and the key.
fn verify_pair(a: &SlotAttest, b: &SlotAttest, pk_attest: &XOnlyPublicKey) -> Result<(), String> {
    if a.unsigned.cohort_id != b.unsigned.cohort_id {
        return Err("attestations are for different cohorts - not an equivocation pair".into());
    }
    if a.unsigned.schedule_root == b.unsigned.schedule_root {
        return Err("attestations commit to the same schedule root - no equivocation".into());
    }
    a.verify(pk_attest)
        .map_err(|e| format!("first BIP-340 verification failed: {e}"))?;
    b.verify(pk_attest)
        .map_err(|e| format!("second BIP-340 verification failed: {e}"))?;
    Ok(())
}

/// Find a keypair whose x-only pubkey has even parity by
/// counter-seeding; `asp_board`/`user_board` reject odd-parity keys.
fn even_parity_keypair(secp: &Secp256k1<secp256k1::All>, seed: u8) -> Keypair {
    for offset in 0u32..1000 {
        let mut bytes = [seed; 32];
        bytes[28..32].copy_from_slice(&offset.to_le_bytes());
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            let kp = Keypair::from_secret_key(secp, &sk);
            if kp.x_only_public_key().1 == Parity::Even {
                return kp;
            }
        }
    }
    unreachable!("even-parity keypair is ~50% likely per attempt; 1000 attempts cannot all fail")
}
