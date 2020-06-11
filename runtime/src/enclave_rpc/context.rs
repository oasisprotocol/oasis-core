//! RPC call context.
use std::{any::Any, sync::Arc};

use io_context::Context as IoContext;

use super::session::SessionInfo;
use crate::rak::RAK;

struct NoRuntimeContext;

/// RPC call context.
pub struct Context {
    /// I/O context.
    pub io_ctx: Arc<IoContext>,
    /// The current RAK if any.
    pub rak: Arc<RAK>,
    /// Information about the session the RPC call was delivered over.
    pub session_info: Option<Arc<SessionInfo>>,
    /// Runtime-specific context.
    pub runtime: Box<dyn Any>,
}

impl Context {
    /// Construct new transaction context.
    pub fn new(
        io_ctx: Arc<IoContext>,
        rak: Arc<RAK>,
        session_info: Option<Arc<SessionInfo>>,
    ) -> Self {
        Self {
            io_ctx,
            rak,
            session_info,
            runtime: Box::new(NoRuntimeContext),
        }
    }
}
