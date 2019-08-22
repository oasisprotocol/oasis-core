//! Runtime call context.
use std::{any::Any, sync::Arc};

use io_context::Context as IoContext;

use super::tags::{Tag, Tags};
use crate::common::roothash::Header;

struct NoRuntimeContext;

/// Transaction context.
pub struct Context<'a> {
    /// I/O context.
    pub io_ctx: Arc<IoContext>,
    /// The block header accompanying this transaction.
    pub header: &'a Header,
    /// Runtime-specific context.
    pub runtime: Box<dyn Any>,

    /// Flag indicating whether to only perform transaction check rather than
    /// running the transaction.
    pub check_only: bool,

    /// List of emitted tags for each transaction.
    tags: Vec<Tags>,
}

impl<'a> Context<'a> {
    /// Construct new transaction context.
    pub fn new(io_ctx: Arc<IoContext>, header: &'a Header, check_only: bool) -> Self {
        Self {
            io_ctx,
            header,
            runtime: Box::new(NoRuntimeContext),
            check_only,
            tags: Vec::new(),
        }
    }

    /// Start a new transaction.
    pub(crate) fn start_transaction(&mut self) {
        self.tags.push(Tags::new());
    }

    /// Close the context and return the emitted tags.
    pub(crate) fn close(self) -> Vec<Tags> {
        self.tags
    }

    /// Emit a runtime-specific indexable tag refering to the specific
    /// transaction which is being processed.
    ///
    /// If multiple tags with the same key are emitted for a transaction, only
    /// the last one will be indexed.
    ///
    /// # Panics
    ///
    /// Calling this method outside of a transaction will panic.
    ///
    pub fn emit_txn_tag<K, V>(&mut self, key: K, value: V)
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        assert!(
            !self.tags.is_empty(),
            "must only be called inside a transaction"
        );

        self.tags
            .last_mut()
            .expect("tags is not empty")
            .push(Tag::new(key.as_ref().to_vec(), value.as_ref().to_vec()))
    }
}
