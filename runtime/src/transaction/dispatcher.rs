//! Runtime transaction batch dispatcher.
use std::{
    collections::BTreeMap,
    sync::{atomic::AtomicBool, Arc},
};

use super::{context::Context, tags::Tags, types::TxnBatch};
use crate::{
    common::crypto::hash::Hash,
    consensus::roothash,
    types::{CheckTxResult, Error as RuntimeError, TransactionWeight},
};

/// Runtime transaction dispatcher trait.
///
/// It defines the interface used by the runtime call dispatcher
/// to process transactions.
pub trait Dispatcher: Send + Sync {
    /// Execute the transactions in the given batch.
    fn execute_batch(
        &self,
        ctx: Context,
        batch: &TxnBatch,
        in_msgs: &[roothash::IncomingMessage],
    ) -> Result<ExecuteBatchResult, RuntimeError>;

    /// Check the transactions in the given batch for validity.
    fn check_batch(
        &self,
        ctx: Context,
        batch: &TxnBatch,
    ) -> Result<Vec<CheckTxResult>, RuntimeError>;

    /// Invoke the finalizer (if any).
    fn finalize(&self, _new_storage_root: Hash) {
        // Default implementation does nothing.
    }

    /// Configure abort batch flag.
    fn set_abort_batch_flag(&mut self, _abort_batch: Arc<AtomicBool>) {
        // Default implementation does nothing.
    }

    /// Process a query.
    fn query(&self, _ctx: Context, _method: &str, _args: Vec<u8>) -> Result<Vec<u8>, RuntimeError> {
        // Default implementation returns an error.
        Err(RuntimeError::new(
            "rhp/dispatcher",
            2,
            "query not supported",
        ))
    }
}

impl<T: Dispatcher + ?Sized> Dispatcher for Box<T> {
    fn execute_batch(
        &self,
        ctx: Context,
        batch: &TxnBatch,
        in_msgs: &[roothash::IncomingMessage],
    ) -> Result<ExecuteBatchResult, RuntimeError> {
        T::execute_batch(&*self, ctx, batch, in_msgs)
    }

    fn check_batch(
        &self,
        ctx: Context,
        batch: &TxnBatch,
    ) -> Result<Vec<CheckTxResult>, RuntimeError> {
        T::check_batch(&*self, ctx, batch)
    }

    fn finalize(&self, new_storage_root: Hash) {
        T::finalize(&*self, new_storage_root)
    }

    fn set_abort_batch_flag(&mut self, abort_batch: Arc<AtomicBool>) {
        T::set_abort_batch_flag(&mut *self, abort_batch)
    }

    fn query(&self, ctx: Context, method: &str, args: Vec<u8>) -> Result<Vec<u8>, RuntimeError> {
        T::query(&*self, ctx, method, args)
    }
}

impl<T: Dispatcher + ?Sized> Dispatcher for Arc<T> {
    fn execute_batch(
        &self,
        ctx: Context,
        batch: &TxnBatch,
        in_msgs: &[roothash::IncomingMessage],
    ) -> Result<ExecuteBatchResult, RuntimeError> {
        T::execute_batch(&*self, ctx, batch, in_msgs)
    }

    fn check_batch(
        &self,
        ctx: Context,
        batch: &TxnBatch,
    ) -> Result<Vec<CheckTxResult>, RuntimeError> {
        T::check_batch(&*self, ctx, batch)
    }

    fn finalize(&self, new_storage_root: Hash) {
        T::finalize(&*self, new_storage_root)
    }

    fn set_abort_batch_flag(&mut self, _abort_batch: Arc<AtomicBool>) {
        unimplemented!()
    }

    fn query(&self, ctx: Context, method: &str, args: Vec<u8>) -> Result<Vec<u8>, RuntimeError> {
        T::query(&*self, ctx, method, args)
    }
}

/// Result of processing an ExecuteTx.
pub struct ExecuteTxResult {
    /// Transaction output.
    pub output: Vec<u8>,
    /// Emitted tags.
    pub tags: Tags,
}

/// Result of processing a batch of ExecuteTx.
pub struct ExecuteBatchResult {
    /// Per-transaction execution results.
    pub results: Vec<ExecuteTxResult>,
    /// Emitted runtime messages.
    pub messages: Vec<roothash::Message>,
    /// Number of processed incoming messages.
    pub in_msgs_count: usize,
    /// Block emitted tags (not emitted by a specific transaction).
    pub block_tags: Tags,
    /// Batch weight limits valid for next round. This is used as a fast-path,
    /// to avoid having the transaction scheduler query these on every round.
    pub batch_weight_limits: Option<BTreeMap<TransactionWeight, u64>>,
}

/// No-op dispatcher.
///
/// This is mainly used by the runtime dispatcher as a fallback in case
/// the runtime's initializer doesn't produce its own dispatcher object.
pub struct NoopDispatcher;

impl NoopDispatcher {
    pub fn new() -> Self {
        NoopDispatcher
    }
}

impl Dispatcher for NoopDispatcher {
    fn execute_batch(
        &self,
        _ctx: Context,
        _batch: &TxnBatch,
        in_msgs: &[roothash::IncomingMessage],
    ) -> Result<ExecuteBatchResult, RuntimeError> {
        Ok(ExecuteBatchResult {
            results: Vec::new(),
            messages: Vec::new(),
            block_tags: Tags::new(),
            batch_weight_limits: None,
            in_msgs_count: in_msgs.len(),
        })
    }

    fn check_batch(
        &self,
        _ctx: Context,
        _batch: &TxnBatch,
    ) -> Result<Vec<CheckTxResult>, RuntimeError> {
        Ok(Vec::new())
    }
}
