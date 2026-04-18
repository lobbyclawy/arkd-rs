//! `/v1/events` — SSE streams (stub).
//!
//! These map the gRPC server-streaming RPCs to `text/event-stream`:
//! - `GET /v1/events`              ⇒ `ArkService.GetEventStream`
//! - `GET /v1/transactions/events` ⇒ `ArkService.GetTransactionsStream`
//! - `GET /v1/subscriptions/{id}`  ⇒ `IndexerService.GetSubscription`

use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
    // .route("/events", get(events_stream))
    // .route("/transactions/events", get(txs_stream))
    // .route("/subscriptions/{id}", get(subscription_stream))
}
