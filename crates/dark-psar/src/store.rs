//! Persistence trait for active cohorts (issue #671).
//!
//! `ActiveCohortStore` abstracts the on-disk side of an
//! `ActiveCohort`. Phase 3 ships an in-memory implementation
//! sufficient for the K=100 / N=12 happy-path test; a Postgres impl
//! is out of scope for AFT and is a documented follow-up.

use std::collections::HashMap;

use crate::boarding::ActiveCohort;
use crate::error::PsarError;

/// Cohort identifier (the `Cohort::id` 32-byte tag) used as the
/// store's primary key.
pub type CohortId = [u8; 32];

pub trait ActiveCohortStore {
    fn save(&mut self, cohort: ActiveCohort) -> Result<(), PsarError>;
    fn load(&self, id: &CohortId) -> Option<&ActiveCohort>;
    fn all(&self) -> Vec<&ActiveCohort>;
}

/// In-memory store. The `RetainedScalars` inside each `ActiveCohort`
/// auto-zeroize on drop (`secp256k1 = 0.29`), so dropping this store
/// also wipes the per-cohort scalars.
#[derive(Default)]
pub struct InMemoryActiveCohortStore {
    cohorts: HashMap<CohortId, ActiveCohort>,
}

impl InMemoryActiveCohortStore {
    pub fn new() -> Self {
        Self {
            cohorts: HashMap::new(),
        }
    }
}

impl ActiveCohortStore for InMemoryActiveCohortStore {
    fn save(&mut self, cohort: ActiveCohort) -> Result<(), PsarError> {
        self.cohorts.insert(cohort.cohort.id, cohort);
        Ok(())
    }

    fn load(&self, id: &CohortId) -> Option<&ActiveCohort> {
        self.cohorts.get(id)
    }

    fn all(&self) -> Vec<&ActiveCohort> {
        self.cohorts.values().collect()
    }
}
