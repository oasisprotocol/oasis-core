//! gRPC message and API definitions.

#[path = "client.rs"]
mod _client;
#[path = "client_grpc.rs"]
mod _client_grpc;
#[path = "storage.rs"]
mod _storage;
#[path = "storage_grpc.rs"]
mod _storage_grpc;

// Re-exports.
pub mod client {
    pub use super::{_client::*, _client_grpc::*};
}
pub mod storage {
    pub use super::{_storage::*, _storage_grpc::*};
}
