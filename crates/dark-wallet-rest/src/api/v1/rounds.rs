//! `/v1/rounds` — round history + VTXO trees (stub).

use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
    // .route("/rounds", get(list_rounds))
    // .route("/rounds/{id}", get(get_round))
    // .route("/rounds/{id}/tree", get(get_tree))
    // .route("/rounds/{id}/commitment-tx", get(get_commitment_tx))
}
