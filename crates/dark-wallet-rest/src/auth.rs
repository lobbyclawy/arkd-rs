//! Bearer-token (macaroon) authentication middleware.
//!
//! This is scaffolding: the extractor pulls the token off the
//! `Authorization: Bearer …` header and attaches it to request extensions.
//! Actual macaroon verification hooks into the same logic as the tonic
//! interceptor once the wallet-rest crate gets a shared macaroon verifier.

use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::Response;

use crate::error::ApiError;
use crate::state::AppState;

/// Opaque token extracted from the `Authorization` header.
#[derive(Clone, Debug)]
pub struct BearerToken(pub String);

/// Reject the request unless an `Authorization: Bearer <token>` header is present.
pub async fn guard_auth(
    State(_state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| ApiError::Unauthorized("missing bearer token".into()))?;

    if token.is_empty() {
        return Err(ApiError::Unauthorized("empty bearer token".into()));
    }

    req.extensions_mut().insert(BearerToken(token));
    Ok(next.run(req).await)
}
