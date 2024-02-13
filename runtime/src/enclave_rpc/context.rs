//! RPC call context.
use std::sync::Arc;

use super::session::SessionInfo;

/// RPC call context.
pub struct Context {
    /// Information about the session the RPC call was delivered over.
    pub session_info: Option<Arc<SessionInfo>>,
}

impl Context {
    /// Construct new transaction context.
    pub fn new(session_info: Option<Arc<SessionInfo>>) -> Self {
        Self { session_info }
    }
}
