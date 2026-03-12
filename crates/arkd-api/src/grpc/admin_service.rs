//! AdminService gRPC implementation — operator API.

use std::sync::Arc;
use std::time::Instant;

use tonic::{Request, Response, Status};
use tracing::info;

use crate::proto::ark_v1::admin_service_server::AdminService as AdminServiceTrait;
use crate::proto::ark_v1::{
    GetRoundDetailsRequest, GetRoundDetailsResponse, GetRoundsRequest, GetRoundsResponse,
    GetStatusRequest, GetStatusResponse,
};

/// AdminService gRPC handler backed by the core application service.
pub struct AdminGrpcService {
    core: Arc<arkd_core::ArkService>,
    started_at: Instant,
}

impl AdminGrpcService {
    /// Create a new AdminGrpcService wrapping the core service.
    pub fn new(core: Arc<arkd_core::ArkService>) -> Self {
        Self {
            core,
            started_at: Instant::now(),
        }
    }
}

#[tonic::async_trait]
impl AdminServiceTrait for AdminGrpcService {
    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        info!("AdminService::GetStatus called");

        let info = self
            .core
            .get_info()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let uptime = self.started_at.elapsed().as_secs();

        Ok(Response::new(GetStatusResponse {
            version: arkd_core::VERSION.to_string(),
            network: info.network,
            uptime_secs: uptime,
            active_rounds: 0,
            total_participants: 0,
            total_vtxos: 0,
            signer_pubkey: info.signer_pubkey,
        }))
    }

    async fn get_round_details(
        &self,
        request: Request<GetRoundDetailsRequest>,
    ) -> Result<Response<GetRoundDetailsResponse>, Status> {
        let req = request.into_inner();
        info!(round_id = %req.round_id, "AdminService::GetRoundDetails called");

        if req.round_id.is_empty() {
            return Err(Status::invalid_argument("round_id is required"));
        }

        // Round details require RoundRepository — not yet wired through ArkService
        Err(Status::not_found(format!(
            "Round {} not found",
            req.round_id
        )))
    }

    async fn get_rounds(
        &self,
        _request: Request<GetRoundsRequest>,
    ) -> Result<Response<GetRoundsResponse>, Status> {
        info!("AdminService::GetRounds called");

        // Returns empty until RoundRepository is wired
        Ok(Response::new(GetRoundsResponse { round_ids: vec![] }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_grpc_service_creation() {
        // Verify we can reference the type
        let _type_check: fn(Arc<arkd_core::ArkService>) -> AdminGrpcService = AdminGrpcService::new;
    }
}
