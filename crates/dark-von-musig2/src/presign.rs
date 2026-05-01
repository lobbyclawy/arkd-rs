//! Participant pre-signing for VON-MuSig2.
//!
//! Given a published schedule `Λ` (#661), the participant's secret key, the
//! operator's VON public key (for `Λ` verification), the key-agg context, and
//! a horizon of `N` message digests, produce `N` pre-signed pairs
//! `(PubNonce_t, PartialSignature_t)` — one per epoch.
//!
//! The participant uses **fresh random nonces per epoch**: only the operator's
//! `(r_{t,b})` are VON-bound. The pre-signed PubNonce is what the operator
//! later combines with their own `R_op` to recover the same `agg_nonce` the
//! participant signed for.

use dark_von::wrapper;
use rand::Rng;
use secp256k1::{PublicKey, SecretKey};

use crate::bip327::key_agg::KeyAggCtx;
use crate::bip327::sign::partial_sign_with_scalars;
use crate::error::VonMusig2Error;
use crate::nonces::{AggNonce, PubNonce};
use crate::setup::PublishedSchedule;
use crate::sign::PartialSignature;

/// Per-epoch pre-signed material from a participant.
#[derive(Clone, Debug)]
pub struct PreSigned {
    pub pub_nonce: PubNonce,
    pub partial_sig: PartialSignature,
}

/// Pre-sign `N` epochs against a published schedule.
///
/// Verifies every entry of `Λ` against the operator's VON public key
/// (`operator_pk_von`); fails on first verification failure.
pub fn presign_horizon<R: Rng + ?Sized>(
    participant_sk: &SecretKey,
    operator_pk_von: &PublicKey,
    ctx: &KeyAggCtx,
    published: &PublishedSchedule,
    messages: &[[u8; 32]],
    rng: &mut R,
) -> Result<Vec<PreSigned>, VonMusig2Error> {
    let public = published.to_dark_von()?;
    if messages.len() != public.n as usize {
        return Err(VonMusig2Error::MalformedPublishedSchedule(
            "messages length disagrees with horizon n",
        ));
    }
    for t in 1..=public.n {
        for b in [1u8, 2u8] {
            let entry = public
                .entry(t, b)
                .ok_or(VonMusig2Error::MalformedPublishedSchedule(
                    "missing schedule entry",
                ))?;
            let x = dark_von::hash::h_nonce(&public.setup_id, t, b);
            wrapper::verify(operator_pk_von, &x, &entry.r_point, &entry.proof)
                .map_err(VonMusig2Error::DarkVon)?;
        }
    }

    let secp = secp256k1::Secp256k1::new();
    let mut out = Vec::with_capacity(public.n as usize);
    for (idx, msg) in messages.iter().enumerate() {
        let t = (idx + 1) as u32;
        // Fresh random nonces per epoch (participant side is not VON-bound).
        let k_p1 = random_secret_key(rng);
        let k_p2 = random_secret_key(rng);
        let r_p1 = PublicKey::from_secret_key(&secp, &k_p1);
        let r_p2 = PublicKey::from_secret_key(&secp, &k_p2);
        let pub_nonce = PubNonce { r1: r_p1, r2: r_p2 };

        // Aggregate with operator's R_t,1 and R_t,2 from Λ.
        let op_e_b1 = public.entry(t, 1).expect("entry checked above");
        let op_e_b2 = public.entry(t, 2).expect("entry checked above");
        let op_pubnonce = PubNonce {
            r1: op_e_b1.r_point,
            r2: op_e_b2.r_point,
        };
        let agg_nonce = AggNonce::sum(&[op_pubnonce, pub_nonce.clone()])?;

        let s = partial_sign_with_scalars(ctx, participant_sk, &k_p1, &k_p2, &agg_nonce, msg)?;
        out.push(PreSigned {
            pub_nonce,
            partial_sig: PartialSignature(s),
        });
    }
    Ok(out)
}

fn random_secret_key<R: Rng + ?Sized>(rng: &mut R) -> SecretKey {
    loop {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            return sk;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::Setup;
    use crate::sign::build_key_agg_ctx;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use secp256k1::Secp256k1;

    fn op_sk() -> SecretKey {
        SecretKey::from_slice(&[0xa1u8; 32]).unwrap()
    }

    fn part_sk() -> SecretKey {
        SecretKey::from_slice(&[0xb2u8; 32]).unwrap()
    }

    #[test]
    fn presign_n4_happy_path() {
        let secp = Secp256k1::new();
        let op = op_sk();
        let part = part_sk();
        let op_pk = PublicKey::from_secret_key(&secp, &op);
        let part_pk = PublicKey::from_secret_key(&secp, &part);

        let ctx = build_key_agg_ctx(&[op_pk, part_pk]).unwrap();
        let (published, _retained) = Setup::run(&op, &[0xc4u8; 32], 4).unwrap();
        let messages: Vec<[u8; 32]> = (0..4u32)
            .map(|i| {
                let mut m = [0u8; 32];
                m[31] = i as u8;
                m
            })
            .collect();
        let mut rng = StdRng::seed_from_u64(0xcafe_d00d);
        let presigned =
            presign_horizon(&part, &op_pk, &ctx, &published, &messages, &mut rng).expect("presign");
        assert_eq!(presigned.len(), 4);
        for p in &presigned {
            // Bytes well-formed
            assert_eq!(p.pub_nonce.to_bytes().len(), 66);
            assert_eq!(p.partial_sig.to_bytes().len(), 32);
        }
    }

    #[test]
    fn presign_rejects_length_mismatch() {
        let secp = Secp256k1::new();
        let op = op_sk();
        let part = part_sk();
        let op_pk = PublicKey::from_secret_key(&secp, &op);
        let part_pk = PublicKey::from_secret_key(&secp, &part);
        let ctx = build_key_agg_ctx(&[op_pk, part_pk]).unwrap();
        let (published, _) = Setup::run(&op, &[0u8; 32], 4).unwrap();
        let messages: Vec<[u8; 32]> = vec![[0u8; 32]; 3]; // wrong length
        let mut rng = StdRng::seed_from_u64(1);
        let result = presign_horizon(&part, &op_pk, &ctx, &published, &messages, &mut rng);
        assert!(matches!(
            result,
            Err(VonMusig2Error::MalformedPublishedSchedule(_))
        ));
    }

    #[test]
    fn presign_rejects_wrong_operator_pk() {
        let secp = Secp256k1::new();
        let op = op_sk();
        let part = part_sk();
        let op_pk = PublicKey::from_secret_key(&secp, &op);
        let part_pk = PublicKey::from_secret_key(&secp, &part);
        let ctx = build_key_agg_ctx(&[op_pk, part_pk]).unwrap();
        let (published, _) = Setup::run(&op, &[0u8; 32], 2).unwrap();
        let messages: Vec<[u8; 32]> = vec![[0u8; 32]; 2];
        let mut rng = StdRng::seed_from_u64(2);
        // Wrong operator pk for verification → all schedule entries reject.
        let bogus_pk =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x99u8; 32]).unwrap());
        let result = presign_horizon(&part, &bogus_pk, &ctx, &published, &messages, &mut rng);
        assert!(matches!(result, Err(VonMusig2Error::DarkVon(_))));
    }

    #[test]
    fn presign_rejects_corrupted_schedule_entry() {
        let secp = Secp256k1::new();
        let op = op_sk();
        let part = part_sk();
        let op_pk = PublicKey::from_secret_key(&secp, &op);
        let part_pk = PublicKey::from_secret_key(&secp, &part);
        let ctx = build_key_agg_ctx(&[op_pk, part_pk]).unwrap();
        let (mut published, _) = Setup::run(&op, &[0u8; 32], 2).unwrap();
        // Replace entry 0's proof with all-zeros (still parses but fails verify).
        published.entries[0].proof1 = vec![0u8; 81];
        let messages: Vec<[u8; 32]> = vec![[0u8; 32]; 2];
        let mut rng = StdRng::seed_from_u64(3);
        let result = presign_horizon(&part, &op_pk, &ctx, &published, &messages, &mut rng);
        // to_dark_von rejects a proof whose gamma byte 0 isn't 0x02/0x03 …
        // actually all-zero parses gamma as 0x00 which Proof::from_slice rejects.
        // Either MalformedPublishedSchedule (parse failure) or DarkVon (verify failure).
        assert!(matches!(
            result,
            Err(VonMusig2Error::MalformedPublishedSchedule(_) | VonMusig2Error::DarkVon(_))
        ));
    }
}
