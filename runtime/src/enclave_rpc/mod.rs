//! Secure inter-enclave RPC.

pub mod client;
pub mod context;
pub mod demux;
pub mod dispatcher;
pub mod session;
pub mod sessions;
mod transport;
pub mod types;

// Re-exports.
pub use self::context::Context;
