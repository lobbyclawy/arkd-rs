//! `/v1/intents` — round-settlement intents (stub).

use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
    // .route("/intents", post(register_intent))
    // .route("/intents/{id}", delete(delete_intent))
    // .route("/intents/{id}/confirm", post(confirm_intent))
    // .route("/intents/{id}/fee", post(estimate_fee))
}
