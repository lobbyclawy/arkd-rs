//! v1 REST surface.

pub mod events;
pub mod exits;
pub mod info;
pub mod intents;
pub mod playground;
pub mod rounds;
pub mod txs;
pub mod vtxos;

use axum::Router;
use utoipa::OpenApi;

use crate::state::AppState;

#[derive(OpenApi)]
#[openapi(
    paths(info::get_info),
    components(schemas(
        crate::dto::ServerInfoDto,
        crate::error::ProblemDetails,
    )),
    tags(
        (name = "info",       description = "Server info and parameters."),
        (name = "vtxos",      description = "Virtual UTXO inspection."),
        (name = "rounds",     description = "Round history and VTXO trees."),
        (name = "txs",        description = "Off-chain Ark transactions (async flow)."),
        (name = "intents",    description = "Batched round-settlement intents."),
        (name = "exits",      description = "Unilateral exit to on-chain."),
        (name = "events",     description = "Server-streamed lifecycle events (SSE)."),
        (name = "playground", description = "Session + faucet helpers (playground only)."),
    )
)]
pub struct V1ApiDoc;

/// Build the full `/v1` Router.
pub fn router() -> Router<AppState> {
    Router::new()
        .merge(info::router())
        .merge(vtxos::router())
        .merge(rounds::router())
        .merge(txs::router())
        .merge(intents::router())
        .merge(exits::router())
        .merge(events::router())
        .merge(playground::router())
}
