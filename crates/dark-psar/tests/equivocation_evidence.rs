//! Security-boundary test (iv): equivocation-evidence verification.
//!
//! Two `slot_attest` tuples sharing a `cohort_id` but committing to
//! different schedule roots both verify under the operator's BIP-340
//! attestation key. The pair is publicly verifiable equivocation
//! evidence; no participant secret is involved. Runs on every CI build
//! via the workspace test job. Companion runnable:
//! `cargo run -p dark-psar --bin equivocation-demo`.

use secp256k1::{Keypair, Parity, Secp256k1, SecretKey, XOnlyPublicKey};

use dark_psar::{compute_schedule_root, CohortMember, SlotAttest, SlotAttestUnsigned, SlotRoot};
use dark_von_musig2::setup::Setup;

const K: u32 = 4;
const N: u32 = 3;

/// Find a keypair whose x-only pubkey has even parity by counter-seeding.
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
    unreachable!("even-parity keypair is ~50% likely per attempt")
}

/// Build an equivocation pair: one legitimate attestation and one
/// signed by the same operator key for the same `cohort_id` but over a
/// conflicting schedule root.
fn make_equivocation_pair() -> (SlotAttest, SlotAttest, XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let asp_kp = even_parity_keypair(&secp, 0x07);
    let asp_sk = SecretKey::from_keypair(&asp_kp);
    let pk_attest = asp_kp.x_only_public_key().0;

    let members: Vec<CohortMember> = (0..K)
        .map(|i| {
            let kp = even_parity_keypair(&secp, 0x10 + i as u8);
            CohortMember {
                user_id: [0x40 + i as u8; 32],
                pk_user: kp.x_only_public_key().0.serialize(),
                slot_index: i,
            }
        })
        .collect();
    let slot_root = SlotRoot::compute(&members).0;

    let cohort_id = [0xc0u8; 32];
    let setup_id_a = [0xa1u8; 32];
    let setup_id_b = [0xb2u8; 32];

    let (schedule_a, _) = Setup::run(&asp_sk, &setup_id_a, N).expect("setup a");
    let (schedule_b, _) = Setup::run(&asp_sk, &setup_id_b, N).expect("setup b");
    let root_a = compute_schedule_root(&cohort_id, &schedule_a).expect("root a");
    let root_b = compute_schedule_root(&cohort_id, &schedule_b).expect("root b");

    let unsigned_a = SlotAttestUnsigned {
        slot_root,
        cohort_id,
        setup_id: setup_id_a,
        n: N,
        k: K,
        schedule_root: root_a.0,
    };
    let unsigned_b = SlotAttestUnsigned {
        setup_id: setup_id_b,
        schedule_root: root_b.0,
        ..unsigned_a
    };

    let attest_a = unsigned_a.sign(&secp, &asp_kp);
    let attest_b = unsigned_b.sign(&secp, &asp_kp);
    (attest_a, attest_b, pk_attest)
}

/// (iv) proper: the pair verifies with exactly two BIP-340 checks and
/// no other state - same cohort, different roots, both signatures
/// valid under `pk_attest`.
#[test]
fn equivocation_pair_verifies_with_two_bip340_checks() {
    let (attest_a, attest_b, pk_attest) = make_equivocation_pair();

    assert_eq!(attest_a.unsigned.cohort_id, attest_b.unsigned.cohort_id);
    assert_ne!(
        attest_a.unsigned.schedule_root,
        attest_b.unsigned.schedule_root
    );
    attest_a.verify(&pk_attest).expect("first BIP-340 check");
    attest_b.verify(&pk_attest).expect("second BIP-340 check");
}

/// The serialized evidence pair is exactly two fixed-width
/// attestations: 2 × 200 B = 400 B (200 B incremental if the
/// legitimate attestation is already public).
#[test]
fn evidence_pair_wire_size_is_pinned() {
    let (attest_a, attest_b, _) = make_equivocation_pair();
    let mut evidence = Vec::new();
    evidence.extend_from_slice(&attest_a.to_bytes());
    evidence.extend_from_slice(&attest_b.to_bytes());
    assert_eq!(SlotAttest::SIZE, 200);
    assert_eq!(evidence.len(), 400);
}

/// Tampering with either signature breaks the corresponding BIP-340
/// check - forged evidence does not verify.
#[test]
fn tampered_evidence_fails_verification() {
    let (attest_a, attest_b, pk_attest) = make_equivocation_pair();

    let mut bytes = attest_b.to_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let forged_b = SlotAttest::from_bytes(&bytes).expect("well-formed length");

    attest_a.verify(&pk_attest).expect("untouched attestation");
    assert!(forged_b.verify(&pk_attest).is_err());
}

/// Two attestations over the same schedule root are not an
/// equivocation pair: the roots agree, so there is nothing to accuse.
/// (BIP-340 signing here is deterministic, so the re-signed
/// attestation is byte-identical too.)
#[test]
fn same_root_is_not_equivocation() {
    let secp = Secp256k1::new();
    let (attest_a, _, _) = make_equivocation_pair();
    let asp_kp = even_parity_keypair(&secp, 0x07);

    let re_signed = attest_a.unsigned.sign(&secp, &asp_kp);
    assert_eq!(
        attest_a.unsigned.schedule_root,
        re_signed.unsigned.schedule_root
    );
    assert_eq!(attest_a.to_bytes(), re_signed.to_bytes());
}
