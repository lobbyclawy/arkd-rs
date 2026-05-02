//! User-side resurface flow (issue #675).
//!
//! A returning user produces an inclusion proof for their slot in the
//! cohort, the ASP verifies it against the cohort's `SlotAttest`
//! `SlotRoot` and the [`crate::EpochArtifacts`] history, and returns
//! a [`ResurfaceArtifact`] containing the latest renewal signature
//! the ASP has produced for that user. The user can:
//!
//! - continue as a VTXO holder by handing the renewal sig forward
//!   into the next epoch's signing flow (#673), or
//! - drop into the unilateral exit path that already lives in
//!   `dark-core` (out of scope here).
//!
//! Phase 4 implements only the cooperative path: the ASP is online
//! and willing to validate the inclusion proof + return the latest
//! sig.

use crate::boarding::ActiveCohort;
use crate::epoch::EpochArtifacts;
use crate::error::PsarError;
use crate::message::derive_message_for_epoch;
use crate::slot_tree::{Slot, SlotInclusionProof};
use secp256k1::{Keypair, Parity};

/// Information returned to a user resurfacing at epoch `t_prime`.
#[derive(Clone, Debug)]
pub struct ResurfaceArtifact {
    pub user_id: [u8; 32],
    pub slot_index: u32,
    pub t_prime: u32,
    pub inclusion_proof: SlotInclusionProof,
    /// 64-byte BIP-340 sig from `EpochArtifacts[t_prime]`, proving the
    /// user's VTXO was renewed at epoch `t_prime`.
    pub renewal_sig_at_t_prime: [u8; 64],
    /// 32-byte renewal message digest the sig was produced over —
    /// recomputable from the cohort's public state for a third-party
    /// verifier.
    pub renewal_msg_at_t_prime: [u8; 32],
}

/// Resurface user `slot_index` at epoch `t_prime`.
///
/// `epoch_artifacts` is the ASP's chronological log of completed
/// epochs (the slot at index `i` corresponds to epoch `i + 1`). The
/// function:
///
/// 1. Validates `t_prime ∈ [1, epoch_artifacts.len()]` (rejects with
///    [`PsarError::ResurfaceFromFuture`] when `t_prime` exceeds the
///    last completed epoch).
/// 2. Validates `user_kp` against the cohort member's stored
///    `pk_user` (with the BIP-340 even-parity convention from #670).
/// 3. Builds an inclusion proof for `slot_index` and verifies it
///    against `active_cohort.slot_root`; rejects with
///    [`PsarError::InclusionProofInvalid`] on mismatch (defensive —
///    the ASP-built tree should always agree).
/// 4. Looks up the user's renewal sig at `t_prime` and the matching
///    `m_{t'}`; returns both inside [`ResurfaceArtifact`].
pub fn user_resurface(
    active_cohort: &ActiveCohort,
    epoch_artifacts: &[EpochArtifacts],
    user_kp: &Keypair,
    slot_index: u32,
    t_prime: u32,
) -> Result<ResurfaceArtifact, PsarError> {
    let current_epoch = epoch_artifacts.len() as u32;
    if t_prime == 0 || t_prime > current_epoch {
        return Err(PsarError::ResurfaceFromFuture {
            t_prime,
            current_epoch,
        });
    }
    let n = active_cohort.cohort.horizon.n;
    if t_prime > n {
        return Err(PsarError::EpochOutOfRange { epoch: t_prime, n });
    }

    // Parity + slot match.
    let (xonly, parity) = user_kp.x_only_public_key();
    if parity == Parity::Odd {
        return Err(PsarError::OddParity);
    }
    let member = active_cohort
        .cohort
        .members
        .get(slot_index as usize)
        .ok_or(PsarError::SlotIndexOutOfRange {
            slot_index,
            k: active_cohort.cohort.k(),
        })?;
    if member.slot_index != slot_index {
        return Err(PsarError::SlotIndexOutOfRange {
            slot_index,
            k: active_cohort.cohort.k(),
        });
    }
    if xonly.serialize() != member.pk_user {
        return Err(PsarError::PubkeyMismatch { slot_index });
    }

    // Inclusion proof.
    let inclusion_proof = SlotInclusionProof::generate(&active_cohort.cohort.members, slot_index)?;
    let leaf = Slot::from_member(member);
    if !inclusion_proof.verify(&active_cohort.slot_root, &leaf) {
        return Err(PsarError::InclusionProofInvalid { slot_index });
    }

    // Lookup the sig + recompute m_{t'}.
    let arts = &epoch_artifacts[(t_prime - 1) as usize];
    let renewal_sig = *arts
        .signatures
        .get(&member.user_id)
        .ok_or(PsarError::UserSigNotFound { epoch: t_prime })?;
    let renewal_msg = derive_message_for_epoch(
        active_cohort.slot_root.as_bytes(),
        &active_cohort.batch_tree_root,
        t_prime,
        n,
    );

    Ok(ResurfaceArtifact {
        user_id: member.user_id,
        slot_index,
        t_prime,
        inclusion_proof,
        renewal_sig_at_t_prime: renewal_sig,
        renewal_msg_at_t_prime: renewal_msg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boarding::asp_board;
    use crate::cohort::{CohortMember, HibernationHorizon};
    use crate::epoch::process_epoch;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use secp256k1::{Keypair, Parity, Secp256k1, SecretKey};

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
        panic!("no even-parity keypair");
    }

    fn build_cohort_and_advance(
        k: u32,
        n: u32,
        epochs_to_run: u32,
    ) -> (Keypair, ActiveCohort, Vec<Keypair>, Vec<EpochArtifacts>) {
        let secp = Secp256k1::new();
        let asp_kp = even_parity_keypair(&secp, 0xa0);
        let horizon = HibernationHorizon::new(n, n.max(12)).unwrap();
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
        let mut rng = StdRng::seed_from_u64(0xdada);
        let mut active = asp_board(
            &asp_kp,
            [0xab; 32],
            members_kps,
            horizon,
            [0xc4; 32],
            None,
            &mut rng,
        )
        .unwrap();
        let mut epoch_artifacts = Vec::with_capacity(epochs_to_run as usize);
        for t in 1..=epochs_to_run {
            epoch_artifacts.push(process_epoch(&mut active, &asp_kp, t).unwrap());
        }
        (asp_kp, active, keypairs, epoch_artifacts)
    }

    /// Issue #675 acceptance: synth ActiveCohort at K=20, N=12, advance
    /// to epoch 6, resurface user 3 successfully.
    #[test]
    fn user_resurface_k20_n12_after_epoch_6() {
        let (_asp_kp, active, keypairs, arts) = build_cohort_and_advance(20, 12, 6);
        let resurfaced = user_resurface(&active, &arts, &keypairs[3], 3, 6).unwrap();

        assert_eq!(resurfaced.t_prime, 6);
        assert_eq!(resurfaced.slot_index, 3);
        assert!(resurfaced.inclusion_proof.verify(
            &active.slot_root,
            &Slot::from_member(&active.cohort.members[3])
        ));
        // Renewal sig from EpochArtifacts at t_prime matches what
        // process_epoch produced.
        assert_eq!(
            resurfaced.renewal_sig_at_t_prime,
            *arts[5].signatures.get(&resurfaced.user_id).unwrap()
        );
    }

    #[test]
    fn user_resurface_rejects_future_epoch() {
        let (_asp_kp, active, keypairs, arts) = build_cohort_and_advance(8, 12, 4);
        // Asking for epoch 5 when only 4 have run is invalid.
        let err = user_resurface(&active, &arts, &keypairs[2], 2, 5).unwrap_err();
        assert!(matches!(
            err,
            PsarError::ResurfaceFromFuture {
                t_prime: 5,
                current_epoch: 4,
            }
        ));
    }

    #[test]
    fn user_resurface_rejects_t_zero() {
        let (_asp_kp, active, keypairs, arts) = build_cohort_and_advance(8, 12, 4);
        let err = user_resurface(&active, &arts, &keypairs[2], 2, 0).unwrap_err();
        assert!(matches!(
            err,
            PsarError::ResurfaceFromFuture { t_prime: 0, .. }
        ));
    }

    #[test]
    fn user_resurface_rejects_wrong_keypair() {
        let secp = Secp256k1::new();
        let (_asp_kp, active, _keypairs, arts) = build_cohort_and_advance(8, 12, 3);
        // A keypair that does not match slot 2.
        let outsider = even_parity_keypair(&secp, 0x99);
        let err = user_resurface(&active, &arts, &outsider, 2, 2).unwrap_err();
        assert!(matches!(err, PsarError::PubkeyMismatch { slot_index: 2 }));
    }

    #[test]
    fn user_resurface_rejects_out_of_range_slot() {
        let (_asp_kp, active, keypairs, arts) = build_cohort_and_advance(8, 12, 3);
        let err = user_resurface(&active, &arts, &keypairs[0], 99, 1).unwrap_err();
        assert!(matches!(
            err,
            PsarError::SlotIndexOutOfRange { slot_index: 99, .. }
        ));
    }
}
