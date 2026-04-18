//! Runtime configuration for the REST daemon.

use std::net::{Ipv4Addr, SocketAddr};

#[derive(Clone, Debug)]
pub struct Config {
    /// Socket to bind the HTTP server on.
    pub listen_addr: SocketAddr,
    /// URL of the upstream dark gRPC server.
    pub dark_grpc_url: String,
    /// Skip macaroon authentication on /v1 routes. Dev-only.
    pub auth_disabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 7072)),
            dark_grpc_url: "http://localhost:7070".to_string(),
            auth_disabled: true,
        }
    }
}
