//! Secure inter-enclave RPC.

pub mod context;
pub mod demux;
pub mod dispatcher;
pub mod macros;
pub mod session;
pub mod types;

// Re-exports.
pub use self::context::Context;
