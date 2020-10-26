//! Runtime call context.
use std::{any::Any, sync::Arc};

use io_context::Context as IoContext;

use super::tags::{Tag, Tags};
use crate::common::roothash::{Header, Message, MessageEvent};

struct NoRuntimeContext;

/// Transaction context.
pub struct Context<'a> {
    /// I/O context.
    pub io_ctx: Arc<IoContext>,
    /// The block header accompanying this transaction.
    pub header: &'a Header,
    /// Results of message processing emitted in the previous round.
    pub message_results: &'a [MessageEvent],
    /// Runtime-specific context.
    pub runtime: Box<dyn Any>,

    /// Flag indicating whether to only perform transaction check rather than
    /// running the transaction.
    pub check_only: bool,

    /// List of emitted tags for each transaction.
    tags: Vec<Tags>,

    /// List of emitted messages.
    messages: Vec<Message>,
}

impl<'a> Context<'a> {
    /// Construct new transaction context.
    pub fn new(
        io_ctx: Arc<IoContext>,
        header: &'a Header,
        message_results: &'a [MessageEvent],
        check_only: bool,
    ) -> Self {
        Self {
            io_ctx,
            header,
            message_results,
            runtime: Box::new(NoRuntimeContext),
            check_only,
            tags: Vec::new(),
            messages: Vec::new(),
        }
    }

    /// Start a new transaction.
    pub fn start_transaction(&mut self) {
        self.tags.push(Tags::new());
    }

    /// Close the context and return the emitted tags and sent roothash messages.
    pub fn close(self) -> (Vec<Tags>, Vec<Message>) {
        (self.tags, self.messages)
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

    /// Emit a message as part of the current round.
    ///
    /// Returns the index of the emitted message which is needed to check for the result of the
    /// emitted message in the next round.
    pub fn emit_message(&mut self, message: Message) -> u32 {
        self.messages.push(message);
        self.messages.len() as u32 - 1
    }
}
