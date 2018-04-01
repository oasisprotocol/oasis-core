//! RPC-specific error types.
use ekiden_rpc_common::api;

/// Error that may occur during request dispatch.
#[derive(Debug, Clone)]
pub struct DispatchError {
    /// Error code.
    pub code: api::PlainClientResponse_Code,
    /// Human-readable message.
    pub message: String,
}

impl DispatchError {
    /// Creates a new dispatch error.
    pub fn new(code: api::PlainClientResponse_Code, message: &str) -> Self {
        DispatchError {
            code,
            message: message.to_string(),
        }
    }
}
