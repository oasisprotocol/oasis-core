//! Ekiden environment.
#[cfg(not(target_env = "sgx"))]
use std::sync::Arc;

#[cfg(not(target_env = "sgx"))]
use grpcio;

/// Ekiden application environment.
///
/// Currently provides things like the used event loop.
pub trait Environment {
    /// Get the gRPC environment.
    #[cfg(not(target_env = "sgx"))]
    fn grpc(&self) -> Arc<grpcio::Environment>;
}
