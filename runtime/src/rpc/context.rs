//! RPC call context.
use std::{any::Any, sync::Arc};

use super::session::SessionInfo;

struct NoRuntimeContext;

/// RPC call context.
pub struct Context {
    /// Information about the session the RPC call was delivered over.
    pub session_info: Option<Arc<SessionInfo>>,
    /// Runtime-specific context.
    pub runtime: Box<Any>,
}

impl Context {
    /// Construct new transaction context.
    pub fn new(session_info: Option<Arc<SessionInfo>>) -> Self {
        Self {
            session_info,
            runtime: Box::new(NoRuntimeContext),
        }
    }
}
