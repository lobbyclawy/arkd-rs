//! `/v1/playground` — session + faucet helpers for the playground deployment (stub).

use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
    // .route("/playground/session", post(create_session))
    // .route("/playground/session/{id}", get(get_session))
    // .route("/playground/faucet", post(faucet))
}
