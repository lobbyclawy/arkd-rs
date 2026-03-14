use serde::{Deserialize, Serialize};

/// A recorded forfeit transaction submitted by a user during a round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForfeitRecord {
    pub id: String,
    pub round_id: String,
    pub vtxo_id: String,
    pub tx_hex: String,
    pub submitted_at: u64,
    pub validated: bool,
}

impl ForfeitRecord {
    pub fn new(round_id: String, vtxo_id: String, tx_hex: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            round_id,
            vtxo_id,
            tx_hex,
            submitted_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            validated: false,
        }
    }

    pub fn mark_validated(&mut self) {
        self.validated = true;
    }
}
