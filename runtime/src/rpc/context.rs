//! RPC call context.
use std::{any::Any, sync::Arc};

use super::session::SessionInfo;
use crate::rak::RAK;

struct NoRuntimeContext;

/// RPC call context.
pub struct Context {
    /// The current RAK if any.
    pub rak: Arc<RAK>,
    /// Information about the session the RPC call was delivered over.
    pub session_info: Option<Arc<SessionInfo>>,
    /// Runtime-specific context.
    pub runtime: Box<Any>,
}

impl Context {
    /// Construct new transaction context.
    pub fn new(rak: Arc<RAK>, session_info: Option<Arc<SessionInfo>>) -> Self {
        Self {
            rak,
            session_info,
            runtime: Box::new(NoRuntimeContext),
        }
    }
}
