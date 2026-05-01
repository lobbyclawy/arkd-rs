//! Per-epoch message derivation `m_t` (issue #670).
//!
//! For each epoch `t ∈ [1, n]` the user pre-signs and the operator
//! signs against a deterministic 32-byte digest `m_t`. Phase 3 derives
//! `m_t` from the cohort context and epoch counter alone:
//!
//! ```text
//! m_t = tagged_hash(
//!     b"DarkPsarMsgV1",
//!     slot_root (32 B) || cohort_id (32 B) || setup_id (32 B) || t (4 B LE u32)
//! )
//! ```
//!
//! Phase 4 (#672) will add the *cohort batch tree structure* into the
//! preimage, binding `m_t` to the user's specific position in the
//! cohort's UTXO output tree. To keep the wire format orthogonal, that
//! work will use a distinct tag (`b"DarkPsarMsgV2"` or similar) so the
//! V1 inputs we lock here never collide with the V2 inputs.

use sha2::{Digest, Sha256};

pub const MESSAGE_TAG: &[u8] = b"DarkPsarMsgV1";

/// Derive the per-epoch message digest `m_t`.
pub fn derive_message_for_epoch(
    slot_root: &[u8; 32],
    cohort_id: &[u8; 32],
    setup_id: &[u8; 32],
    t: u32,
) -> [u8; 32] {
    let tag_hash = Sha256::digest(MESSAGE_TAG);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(slot_root);
    hasher.update(cohort_id);
    hasher.update(setup_id);
    hasher.update(t.to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_tag_value() {
        assert_eq!(MESSAGE_TAG, b"DarkPsarMsgV1");
    }

    #[test]
    fn determinism() {
        let s = [0x11; 32];
        let c = [0x22; 32];
        let i = [0x33; 32];
        assert_eq!(
            derive_message_for_epoch(&s, &c, &i, 7),
            derive_message_for_epoch(&s, &c, &i, 7),
        );
    }

    #[test]
    fn distinct_inputs_distinct_outputs() {
        let s = [0x11; 32];
        let c = [0x22; 32];
        let i = [0x33; 32];
        assert_ne!(
            derive_message_for_epoch(&s, &c, &i, 1),
            derive_message_for_epoch(&s, &c, &i, 2),
        );
        assert_ne!(
            derive_message_for_epoch(&s, &c, &i, 1),
            derive_message_for_epoch(&[0x99; 32], &c, &i, 1),
        );
        assert_ne!(
            derive_message_for_epoch(&s, &c, &i, 1),
            derive_message_for_epoch(&s, &[0xaa; 32], &i, 1),
        );
        assert_ne!(
            derive_message_for_epoch(&s, &c, &i, 1),
            derive_message_for_epoch(&s, &c, &[0xbb; 32], 1),
        );
    }

    #[test]
    fn t_endianness_is_little() {
        let s = [0u8; 32];
        let c = [0u8; 32];
        let i = [0u8; 32];
        assert_ne!(
            derive_message_for_epoch(&s, &c, &i, 1),
            derive_message_for_epoch(&s, &c, &i, 0x0100_0000),
        );
    }
}
