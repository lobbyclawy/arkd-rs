//! `/v1/exits` — unilateral exit to on-chain (stub).

use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
    // .route("/exits", post(request_exit))
}
