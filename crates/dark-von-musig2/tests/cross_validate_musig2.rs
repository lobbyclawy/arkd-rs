//! Cross-validate our handroll BIP-327 against `musig2 = "0.3.1"` (dev-dep).
//!
//! `musig2 = "0.3.1"` re-exports types from its own `secp256k1 = "0.31"`
//! transitive dep, while our crate uses the workspace pin `secp256k1 = "0.29"`.
//! The two SECP256K1 types are byte-compatible but not Rust-typecompatible,
//! so this test crosses the boundary via 33-byte / 32-byte / 64-byte / 66-byte
//! wire conversions. That's *exactly* the wire-format gate ADR-0008's
//! cross-validation strategy specifies.

use dark_von_musig2::nonces::{AggNonce as OurAggNonce, PubNonce as OurPubNonce};
use dark_von_musig2::sign::{
    aggregate as our_aggregate, build_key_agg_ctx, pub_nonces_from_von, sign_partial_with_von,
    PartialSignature as OurPartialSignature,
};
use musig2::secp256k1 as msecp;
use musig2::{
    BinaryEncoding, KeyAggContext as MusigKeyAggCtx, PubNonce as MusigPubNonce, SecNonce,
};
use secp256k1 as ksecp;

const MSG: [u8; 32] = [0x42; 32];

fn fixed_op_sk_29() -> ksecp::SecretKey {
    ksecp::SecretKey::from_slice(&[0xa1u8; 32]).unwrap()
}

#[allow(deprecated)]
fn fixed_part_sk_31() -> msecp::SecretKey {
    // `from_slice` is deprecated in secp256k1 0.31 in favour of `from_byte_array`,
    // but musig2 = 0.3.1 still re-exports the old surface. We cross the version
    // boundary here, so accept the deprecation locally.
    msecp::SecretKey::from_slice(&[0xb2u8; 32]).unwrap()
}

fn pk_31_from_29(pk: &ksecp::PublicKey) -> msecp::PublicKey {
    msecp::PublicKey::from_slice(&pk.serialize()).expect("33-byte compressed roundtrip")
}

fn pk_29_from_31(pk: &msecp::PublicKey) -> ksecp::PublicKey {
    ksecp::PublicKey::from_slice(&pk.serialize()).expect("33-byte compressed roundtrip")
}

#[test]
fn key_agg_matches_musig2() {
    let secp29 = ksecp::Secp256k1::new();
    let op_pk = ksecp::PublicKey::from_secret_key(&secp29, &fixed_op_sk_29());
    let part_pk_31 =
        msecp::PublicKey::from_secret_key(&msecp::Secp256k1::new(), &fixed_part_sk_31());
    let part_pk = pk_29_from_31(&part_pk_31);

    let our_ctx = build_key_agg_ctx(&[op_pk, part_pk]).expect("our key_agg");

    let musig_pks = vec![pk_31_from_29(&op_pk), part_pk_31];
    let musig_ctx = MusigKeyAggCtx::new(musig_pks).expect("musig2 key_agg");
    let musig_q: msecp::PublicKey = musig_ctx.aggregated_pubkey();

    assert_eq!(
        our_ctx.aggregated_pubkey(),
        musig_q.serialize(),
        "aggregated pubkey diverges from musig2 = 0.3.1"
    );
}

#[test]
fn key_agg_matches_musig2_three_signers() {
    let secp29 = ksecp::Secp256k1::new();
    let our_pks: Vec<ksecp::PublicKey> = [0x11u8, 0x22, 0x33]
        .iter()
        .map(|b| {
            ksecp::PublicKey::from_secret_key(
                &secp29,
                &ksecp::SecretKey::from_slice(&[*b; 32]).unwrap(),
            )
        })
        .collect();
    let musig_pks: Vec<msecp::PublicKey> = our_pks.iter().map(pk_31_from_29).collect();

    let our_ctx = build_key_agg_ctx(&our_pks).expect("our key_agg");
    let musig_ctx = MusigKeyAggCtx::new(musig_pks).expect("musig2 key_agg");
    let musig_q: msecp::PublicKey = musig_ctx.aggregated_pubkey();

    assert_eq!(our_ctx.aggregated_pubkey(), musig_q.serialize());
}

#[test]
fn two_of_two_operator_handroll_participant_musig2_verifies() {
    let secp29 = ksecp::Secp256k1::new();
    let secp31 = msecp::Secp256k1::new();

    let op_sk_29 = fixed_op_sk_29();
    let op_pk_29 = ksecp::PublicKey::from_secret_key(&secp29, &op_sk_29);
    let op_pk_31 = pk_31_from_29(&op_pk_29);

    let part_sk_31 = fixed_part_sk_31();
    let part_pk_31 = msecp::PublicKey::from_secret_key(&secp31, &part_sk_31);
    let part_pk_29 = pk_29_from_31(&part_pk_31);

    // Build matching key-agg contexts both sides.
    let our_ctx = build_key_agg_ctx(&[op_pk_29, part_pk_29]).expect("our key_agg");
    let musig_ctx = MusigKeyAggCtx::new(vec![op_pk_31, part_pk_31]).expect("musig2 key_agg");

    // Operator: simulate VON output by deterministic scalars.
    let k1_op = ksecp::SecretKey::from_slice(&[0xc1u8; 32]).unwrap();
    let k2_op = ksecp::SecretKey::from_slice(&[0xc2u8; 32]).unwrap();
    let r1_op = ksecp::PublicKey::from_secret_key(&secp29, &k1_op);
    let r2_op = ksecp::PublicKey::from_secret_key(&secp29, &k2_op);
    let op_pubnonce_29 = pub_nonces_from_von(r1_op, r2_op);

    // Participant: standard musig2 nonce gen.
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut seed);
    let part_secnonce: SecNonce = SecNonce::build(musig2::NonceSeed(seed))
        .with_seckey(part_sk_31)
        .with_message(&MSG)
        .build();
    let part_pubnonce_31: MusigPubNonce = part_secnonce.public_nonce();
    let part_pn_bytes: [u8; 66] = part_pubnonce_31.to_bytes();

    // Our agg nonce uses 0.29 types.
    let part_pubnonce_29 = OurPubNonce::from_slice(&part_pn_bytes).unwrap();
    let our_agg_nonce = OurAggNonce::sum(&[op_pubnonce_29.clone(), part_pubnonce_29]).unwrap();

    // musig2 agg nonce uses 0.31 types.
    let op_pubnonce_31 = MusigPubNonce::from_bytes(&op_pubnonce_29.to_bytes()).expect("pubnonce");
    let musig_agg_nonce: musig2::AggNonce =
        [&op_pubnonce_31, &part_pubnonce_31].iter().copied().sum();

    // Wire-format gate: our agg nonce bytes equal musig2's.
    assert_eq!(
        our_agg_nonce.to_bytes(),
        musig_agg_nonce.to_bytes(),
        "agg nonce wire format diverges"
    );

    // Operator partial sig via our handroll.
    let op_partial: OurPartialSignature =
        sign_partial_with_von(&our_ctx, &op_sk_29, (&k1_op, &k2_op), &our_agg_nonce, &MSG)
            .expect("our partial sig");

    // Participant partial sig via musig2 = 0.3.1.
    let part_partial: musig2::PartialSignature =
        musig2::sign_partial(&musig_ctx, part_sk_31, part_secnonce, &musig_agg_nonce, MSG)
            .expect("musig2 partial sig");

    // Aggregate via musig2's aggregator (the canonical wire ground truth).
    let op_partial_for_musig: musig2::PartialSignature =
        musig2::PartialSignature::from_slice(&op_partial.to_bytes()).expect("partial sig wire");
    let final_sig: musig2::CompactSignature = musig2::aggregate_partial_signatures(
        &musig_ctx,
        &musig_agg_nonce,
        [op_partial_for_musig, part_partial],
        MSG,
    )
    .expect("aggregate");

    let agg_pk_31: msecp::PublicKey = musig_ctx.aggregated_pubkey();
    let sig_bytes: [u8; 64] = final_sig.to_bytes();
    musig2::verify_single(agg_pk_31, sig_bytes, MSG).expect("BIP-340 verifies");

    // Our own aggregator must produce byte-identical output.
    let mut part_partial_bytes = [0u8; 32];
    part_partial_bytes.copy_from_slice(&part_partial.serialize());
    let part_partial_29 = OurPartialSignature::from_slice(&part_partial_bytes).unwrap();
    let our_final = our_aggregate(
        &our_ctx,
        &our_agg_nonce,
        &MSG,
        &[op_partial, part_partial_29],
    )
    .expect("our aggregator");
    assert_eq!(our_final, sig_bytes, "our aggregator drift vs musig2's");
}
