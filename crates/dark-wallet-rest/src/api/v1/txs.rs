//! `/v1/txs` — async off-chain Ark transactions (stub).

use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
    // .route("/txs", post(submit_tx))
    // .route("/txs/{id}", get(get_tx))
    // .route("/txs/{id}/finalize", post(finalize_tx))
}
