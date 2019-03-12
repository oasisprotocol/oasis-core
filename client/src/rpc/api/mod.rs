//! gRPC message and API definitions.

pub mod enclaverpc;
pub mod enclaverpc_grpc;

// Re-exports.
pub use self::{enclaverpc::*, enclaverpc_grpc::*};
