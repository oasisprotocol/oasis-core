//! Runtime call context.
use std::{any::Any, sync::Arc};

use io_context::Context as IoContext;

use crate::common::roothash::Header;

struct NoRuntimeContext;

/// Transaction context.
pub struct Context<'a> {
    /// I/O context.
    pub io_ctx: Arc<IoContext>,
    /// The block header accompanying this transaction.
    pub header: &'a Header,
    /// Runtime-specific context.
    pub runtime: Box<Any>,
}

impl<'a> Context<'a> {
    /// Construct new transaction context.
    pub fn new(io_ctx: Arc<IoContext>, header: &'a Header) -> Self {
        Self {
            io_ctx,
            header,
            runtime: Box::new(NoRuntimeContext),
        }
    }
}
