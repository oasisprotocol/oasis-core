//! gRPC message and API definitions.

#[path = "storage.rs"]
mod _storage;
#[path = "storage_grpc.rs"]
mod _storage_grpc;

// Re-exports.
pub mod storage {
    pub use super::{_storage::*, _storage_grpc::*};
}
