//! Runtime call context.
use std::{any::Any, sync::Arc};

use io_context::Context as IoContext;

use crate::{
    common::roothash::Header,
    types::{Tag, TAG_TXN_INDEX_BLOCK},
};

struct NoRuntimeContext;

/// Transaction context.
pub struct Context<'a> {
    /// I/O context.
    pub io_ctx: Arc<IoContext>,
    /// The block header accompanying this transaction.
    pub header: &'a Header,
    /// Runtime-specific context.
    pub runtime: Box<Any>,

    /// List of emitted tags.
    pub(crate) tags: Vec<Tag>,
    /// Index of the current transaction. Set by the dispatcher while
    /// processing a batch.
    pub(crate) txn_index: i32,
}

impl<'a> Context<'a> {
    /// Construct new transaction context.
    pub fn new(io_ctx: Arc<IoContext>, header: &'a Header) -> Self {
        Self {
            io_ctx,
            header,
            runtime: Box::new(NoRuntimeContext),
            tags: Vec::new(),
            txn_index: TAG_TXN_INDEX_BLOCK,
        }
    }

    fn emit_tag(&mut self, txn_index: i32, key: &[u8], value: &[u8]) {
        self.tags.push(Tag {
            txn_index,
            key: key.to_vec(),
            value: value.to_vec(),
        })
    }

    /// Emit a runtime-specific indexable tag refering to the block in which
    /// the transaction is being processed.
    ///
    /// If multiple tags with the same key are emitted for a block, only the
    /// last one will be indexed.
    pub fn emit_block_tag<K, V>(&mut self, key: K, value: V)
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.emit_tag(TAG_TXN_INDEX_BLOCK, key.as_ref(), value.as_ref());
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
        if self.txn_index < 0 {
            panic!("must only be called inside a transaction");
        }

        self.emit_tag(self.txn_index, key.as_ref(), value.as_ref());
    }
}
