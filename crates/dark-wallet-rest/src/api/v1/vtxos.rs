//! `/v1/vtxos` — VTXO inspection (stub).

use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
    // .route("/vtxos", get(list_vtxos))
    // .route("/vtxos/{outpoint}/chain", get(vtxo_chain))
}
