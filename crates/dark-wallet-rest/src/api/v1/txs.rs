//! `/v1/txs` — async off-chain Ark transactions.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::dto::{
    FinalizeTxRequestDto, PendingTxResponseDto, SubmitTxRequestDto, SubmitTxResponseDto,
};
use crate::error::{ApiError, ApiResult, ProblemDetails};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/txs", post(submit_tx))
        .route("/txs/{id}", get(get_tx))
        .route("/txs/{id}/finalize", post(finalize_tx))
}

#[utoipa::path(
    post,
    path = "/txs",
    tag = "txs",
    summary = "Submit a signed Ark virtual tx",
    description = "Submits a hex-encoded signed Ark tx to the server. The server returns the \
                   assigned Ark txid. Call `/v1/txs/{id}/finalize` with the final checkpoint \
                   transactions to complete the flow.",
    request_body = SubmitTxRequestDto,
    responses(
        (status = 200, description = "Accepted", body = SubmitTxResponseDto),
        (status = 400, description = "Bad request", body = ProblemDetails),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn submit_tx(
    State(state): State<AppState>,
    Json(req): Json<SubmitTxRequestDto>,
) -> ApiResult<Json<SubmitTxResponseDto>> {
    if req.signed_ark_tx.is_empty() {
        return Err(ApiError::BadRequest(
            "signed_ark_tx must not be empty".into(),
        ));
    }
    let mut ark = state.ark().await;
    let ark_txid = ark.submit_tx(&req.signed_ark_tx).await?;
    Ok(Json(SubmitTxResponseDto { ark_txid }))
}

#[utoipa::path(
    post,
    path = "/txs/{id}/finalize",
    tag = "txs",
    summary = "Finalize a pending Ark tx",
    params(("id" = String, Path, description = "Ark txid previously returned by POST /txs")),
    request_body = FinalizeTxRequestDto,
    responses(
        (status = 204, description = "Finalized"),
        (status = 400, description = "Bad request", body = ProblemDetails),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn finalize_tx(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(_req): Json<FinalizeTxRequestDto>,
) -> ApiResult<axum::http::StatusCode> {
    let mut ark = state.ark().await;
    ark.finalize_tx(&id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/txs/{id}",
    tag = "txs",
    summary = "Query a pending Ark tx",
    description = "Placeholder for a future query endpoint. For now this is a stub \
                   that mirrors `ArkService.GetPendingTx` when it becomes available.",
    params(("id" = String, Path, description = "Ark txid")),
    responses(
        (status = 200, description = "Pending tx status", body = PendingTxResponseDto),
        (status = 501, description = "Not implemented", body = ProblemDetails),
    )
)]
pub async fn get_tx(
    State(_state): State<AppState>,
    Path(_id): Path<String>,
) -> ApiResult<Json<PendingTxResponseDto>> {
    Err(ApiError::Internal(
        "GetPendingTx upstream wiring not yet exposed through dark-client".into(),
    ))
}
