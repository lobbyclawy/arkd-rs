//! Cohort lifecycle event-driven state machine (issue #674).
//!
//! The [`CohortState`] enum (in [`crate::cohort`]) describes *where*
//! a cohort sits; this module describes *what* drives transitions
//! between states. Every transition is gated by a
//! [`CohortLifecycleEvent`] and produces a fresh `CohortState` (or a
//! [`PsarError::InvalidLifecycleEvent`] when the event does not apply).
//!
//! ```text
//! ┌──────────┐ SlotAttestSigned       ┌────────────┐ AttestPublished ┌────────┐
//! │ Forming  │───────────────────────▶│ Committed  │────────────────▶│ Active │
//! └──────────┘                        └────────────┘                 └────┬───┘
//!                                                                         │ EpochStarted(t)
//!                                                                         ▼
//!                                                              ┌──────────────────┐
//!                                                              │ InProgress(t)    │
//!                                                              └────────┬─────────┘
//!                                                                       │ EpochCommitted
//!                                                                       ▼
//!                                                              ┌────────────┐
//!                                                              │   Active   │
//!                                                              └────┬───────┘
//!                                                                   │ HorizonExhausted
//!                                                                   ▼
//!                                                              ┌────────────┐
//!                                                              │ Concluded  │
//!                                                              └────────────┘
//! ```

use serde::{Deserialize, Serialize};

use crate::cohort::CohortState;
use crate::error::PsarError;

/// Events that can advance a cohort through its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CohortLifecycleEvent {
    /// The ASP has signed `SlotAttest` for this cohort.
    SlotAttestSigned,
    /// The on-chain attestation publication has confirmed.
    AttestPublished,
    /// Epoch `t` processing has begun.
    EpochStarted(u32),
    /// The current epoch's renewal sigs have all been produced.
    EpochCommitted,
    /// The horizon has been fully consumed (`t == n`).
    HorizonExhausted,
}

/// Apply `event` to `state`, returning the next state on success.
///
/// Unrecognised `(state, event)` pairs return
/// [`PsarError::InvalidLifecycleEvent`] without mutating any caller
/// state — the function is pure.
pub fn next_state(
    state: CohortState,
    event: CohortLifecycleEvent,
) -> Result<CohortState, PsarError> {
    use CohortLifecycleEvent::*;
    use CohortState::*;
    match (state, event) {
        (Forming, SlotAttestSigned) => Ok(Committed),
        (Committed, AttestPublished) => Ok(Active),
        (Active, EpochStarted(t)) => Ok(InProgress(t)),
        (InProgress(_), EpochCommitted) => Ok(Active),
        (Active, HorizonExhausted) => Ok(Concluded),
        (s, e) => Err(PsarError::InvalidLifecycleEvent { state: s, event: e }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_cycle_with_two_epochs() {
        let mut s = CohortState::Forming;
        for (event, expected) in [
            (
                CohortLifecycleEvent::SlotAttestSigned,
                CohortState::Committed,
            ),
            (CohortLifecycleEvent::AttestPublished, CohortState::Active),
            (
                CohortLifecycleEvent::EpochStarted(1),
                CohortState::InProgress(1),
            ),
            (CohortLifecycleEvent::EpochCommitted, CohortState::Active),
            (
                CohortLifecycleEvent::EpochStarted(2),
                CohortState::InProgress(2),
            ),
            (CohortLifecycleEvent::EpochCommitted, CohortState::Active),
            (
                CohortLifecycleEvent::HorizonExhausted,
                CohortState::Concluded,
            ),
        ] {
            s = next_state(s, event).expect("legal");
            assert_eq!(s, expected);
        }
    }

    #[test]
    fn rejects_skip_forming_to_active() {
        let err =
            next_state(CohortState::Forming, CohortLifecycleEvent::AttestPublished).unwrap_err();
        match err {
            PsarError::InvalidLifecycleEvent { state, event } => {
                assert_eq!(state, CohortState::Forming);
                assert_eq!(event, CohortLifecycleEvent::AttestPublished);
            }
            other => panic!("expected InvalidLifecycleEvent, got {other:?}"),
        }
    }

    #[test]
    fn rejects_double_attest_published() {
        // Active is reached after AttestPublished; firing it again should fail.
        let s = next_state(CohortState::Forming, CohortLifecycleEvent::SlotAttestSigned).unwrap();
        let s = next_state(s, CohortLifecycleEvent::AttestPublished).unwrap();
        let err = next_state(s, CohortLifecycleEvent::AttestPublished).unwrap_err();
        assert!(matches!(err, PsarError::InvalidLifecycleEvent { .. }));
    }

    #[test]
    fn rejects_concluded_terminal() {
        let s = CohortState::Concluded;
        for ev in [
            CohortLifecycleEvent::SlotAttestSigned,
            CohortLifecycleEvent::AttestPublished,
            CohortLifecycleEvent::EpochStarted(1),
            CohortLifecycleEvent::EpochCommitted,
            CohortLifecycleEvent::HorizonExhausted,
        ] {
            assert!(
                next_state(s, ev).is_err(),
                "Concluded must be terminal for {ev:?}"
            );
        }
    }

    #[test]
    fn epoch_started_carries_t() {
        let s = next_state(CohortState::Active, CohortLifecycleEvent::EpochStarted(7)).unwrap();
        assert_eq!(s, CohortState::InProgress(7));
    }
}
