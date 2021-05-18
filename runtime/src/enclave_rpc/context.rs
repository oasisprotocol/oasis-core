//! RPC call context.
use std::{any::Any, sync::Arc};

use io_context::Context as IoContext;

use super::session::SessionInfo;
use crate::rak::RAK;

struct NoRuntimeContext;

/// RPC call context.
pub struct Context<'a> {
    /// I/O context.
    pub io_ctx: Arc<IoContext>,
    /// Tokio runtime.
    pub tokio: &'a tokio::runtime::Runtime,
    /// The current RAK if any.
    pub rak: Arc<RAK>,
    /// Information about the session the RPC call was delivered over.
    pub session_info: Option<Arc<SessionInfo>>,
    /// Runtime-specific context.
    pub runtime: Box<dyn Any>,
}

impl<'a> Context<'a> {
    /// Construct new transaction context.
    pub fn new(
        io_ctx: Arc<IoContext>,
        tokio: &'a tokio::runtime::Runtime,
        rak: Arc<RAK>,
        session_info: Option<Arc<SessionInfo>>,
    ) -> Self {
        Self {
            io_ctx,
            tokio,
            rak,
            session_info,
            runtime: Box::new(NoRuntimeContext),
        }
    }
}
