//! Shared support for the PSAR end-to-end tests (`e2e_psar_n12`,
//! `e2e_psar_n4_smoke`). Lives at workspace level — not registered in
//! `Cargo.toml` `[[test]]` because every consumer pulls it in via
//! `#[path = "_psar_support.rs"] mod support;`.

#![allow(dead_code)]

use bitcoin::secp256k1::Secp256k1;
use dark_psar::boarding::asp_board;
use dark_psar::cohort::{CohortMember, HibernationHorizon};
use dark_psar::epoch::{process_epoch, EpochArtifacts};
use dark_psar::message::derive_message_for_epoch;
use dark_psar::ActiveCohort;
use rand::rngs::StdRng;
use rand::SeedableRng;
use secp256k1::{
    schnorr::Signature, Keypair, Message, Parity, PublicKey, SecretKey, XOnlyPublicKey,
};

/// Lift a BIP-340 x-only key to an even-parity 33-byte compressed
/// PublicKey. Mirrors the convention `dark_psar` uses internally.
fn lift_xonly_to_even(pk: &XOnlyPublicKey) -> PublicKey {
    let xb = pk.serialize();
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(&xb);
    PublicKey::from_slice(&compressed).expect("x-only lifts to a valid even-parity point")
}

/// Find a SecretKey with even-parity x-only pubkey by counter-seeding.
pub fn even_parity_keypair(secp: &Secp256k1<secp256k1::All>, seed: u8) -> Keypair {
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
    panic!("no even-parity keypair found within counter range");
}

/// Build a `(ASP keypair, ActiveCohort, user keypair list)` triple via
/// the canonical ASP-side flow, with deterministic seeds.
pub fn board_cohort(k: u32, n: u32, seed: u8) -> (Keypair, ActiveCohort, Vec<Keypair>) {
    let secp = Secp256k1::new();
    let asp_kp = even_parity_keypair(&secp, seed);
    let horizon = HibernationHorizon::new(n, n.max(12)).expect("horizon");
    let mut keypairs = Vec::with_capacity(k as usize);
    let mut members_kps = Vec::with_capacity(k as usize);
    for i in 0..k {
        let kp = even_parity_keypair(&secp, (i + 1) as u8);
        let xonly = kp.x_only_public_key().0.serialize();
        let mut user_id = [0u8; 32];
        user_id[0] = ((i >> 8) & 0xff) as u8;
        user_id[1] = (i & 0xff) as u8;
        keypairs.push(kp);
        members_kps.push((
            CohortMember {
                user_id,
                pk_user: xonly,
                slot_index: i,
            },
            kp,
        ));
    }
    let mut rng = StdRng::seed_from_u64(seed as u64);
    let active = asp_board(
        &asp_kp,
        [seed; 32],
        members_kps,
        horizon,
        [0xc4; 32],
        None,
        &mut rng,
    )
    .expect("asp_board");
    (asp_kp, active, keypairs)
}

/// Verify a per-user BIP-340 signature against the 2-of-2 (asp + user)
/// aggregate Taproot key. Panics on failure with epoch context.
pub fn verify_renewal_sig(
    secp: &Secp256k1<secp256k1::All>,
    asp_xonly: &XOnlyPublicKey,
    user_xonly_bytes: &[u8; 32],
    m_t: &[u8; 32],
    sig_bytes: &[u8; 64],
    epoch: u32,
) {
    use dark_von_musig2::sign::build_key_agg_ctx;
    let asp_full = lift_xonly_to_even(asp_xonly);
    let user_xonly = XOnlyPublicKey::from_slice(user_xonly_bytes).expect("user pubkey");
    let user_full = lift_xonly_to_even(&user_xonly);
    let ctx = build_key_agg_ctx(&[asp_full, user_full]).expect("key_agg");
    let agg_xonly_bytes = ctx.x_only_pubkey();
    let agg_xonly = XOnlyPublicKey::from_slice(&agg_xonly_bytes).expect("agg xonly");
    let sig = Signature::from_slice(sig_bytes).expect("sig parse");
    let msg = Message::from_digest(*m_t);
    secp.verify_schnorr(&sig, &msg, &agg_xonly)
        .unwrap_or_else(|e| panic!("epoch {epoch}: BIP-340 verify failed: {e}"));
}

/// Run the full PSAR pipeline for `(K, N, seed)`: board the cohort,
/// process every epoch, and verify each emitted signature against the
/// cohort's aggregated Taproot key. Returns the per-epoch artifact log
/// alongside elapsed time so callers can assert acceptance budgets.
pub fn run_pipeline(k: u32, n: u32, seed: u8) -> (Vec<EpochArtifacts>, std::time::Duration) {
    let secp = Secp256k1::new();
    let (asp_kp, mut active, _keypairs) = board_cohort(k, n, seed);
    let asp_xonly = asp_kp.x_only_public_key().0;

    let mut log = Vec::with_capacity(n as usize);
    let start = std::time::Instant::now();
    for t in 1..=n {
        let arts = process_epoch(&mut active, &asp_kp, t).expect("process_epoch");
        assert!(
            arts.fully_complete(k as usize),
            "epoch {t}: missing or failed user sigs"
        );
        let m_t =
            derive_message_for_epoch(active.slot_root.as_bytes(), &active.batch_tree_root, t, n);
        for member in &active.cohort.members {
            let sig = arts
                .signatures
                .get(&member.user_id)
                .expect("sig present for member");
            verify_renewal_sig(&secp, &asp_xonly, &member.pk_user, &m_t, sig, t);
        }
        log.push(arts);
    }
    let elapsed = start.elapsed();
    (log, elapsed)
}
