//! `/v1/playground` — session + faucet helpers for the playground deployment.
//!
//! Intentionally kept as a placeholder: the playground session + faucet model
//! (per-visitor macaroon issuance, rate-limited signet drips, short-lived
//! state) is a deployment concern that should be designed separately from the
//! REST surface. When implemented, routes land here without disturbing the
//! rest of the API.

use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
}
