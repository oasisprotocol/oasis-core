//! Runtime transaction batch dispatcher.
use std::sync::{atomic::AtomicBool, Arc};

use super::{context::Context, tags::Tags, types::TxnBatch};
use crate::{
    common::crypto::hash::Hash,
    consensus::roothash,
    types::{CheckTxResult, Error as RuntimeError},
};

/// Runtime transaction dispatcher trait.
///
/// It defines the interface used by the runtime call dispatcher
/// to process transactions.
pub trait Dispatcher: Send + Sync {
    /// Whether dispatch is supported by this dispatcher.
    fn is_supported(&self) -> bool {
        true
    }

    /// Execute the transactions in the given batch.
    ///
    /// # Consensus Layer State Integrity
    ///
    /// Before this method is invoked, consensus layer state integrity verification is performed.
    fn execute_batch(
        &self,
        ctx: Context,
        batch: &TxnBatch,
        in_msgs: &[roothash::IncomingMessage],
    ) -> Result<ExecuteBatchResult, RuntimeError>;

    /// Schedule and execute transactions in the given batch.
    ///
    /// The passed batch is an initial batch. In case the runtime needs additional items it should
    /// request them from the host.
    ///
    /// # Consensus Layer State Integrity
    ///
    /// Before this method is invoked, consensus layer state integrity verification is performed.
    fn schedule_and_execute_batch(
        &self,
        _ctx: Context,
        _initial_batch: &mut TxnBatch,
        _in_msgs: &[roothash::IncomingMessage],
    ) -> Result<ExecuteBatchResult, RuntimeError> {
        Err(RuntimeError::new(
            "rhp/dispatcher",
            3,
            "scheduling not supported",
        ))
    }

    /// Check the transactions in the given batch for validity.
    ///
    /// # Consensus Layer State Integrity
    ///
    /// No consensus layer state integrity verification is performed for queries by default. The
    /// runtime dispatcher implementation should perform integrity verification if needed on a
    /// query-by-query basis.
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
    ///
    /// # Consensus Layer State Integrity
    ///
    /// No consensus layer state integrity verification is performed for queries by default. The
    /// runtime dispatcher implementation should perform integrity verification if needed on a
    /// query-by-query basis.
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
    fn is_supported(&self) -> bool {
        T::is_supported(&**self)
    }

    fn execute_batch(
        &self,
        ctx: Context,
        batch: &TxnBatch,
        in_msgs: &[roothash::IncomingMessage],
    ) -> Result<ExecuteBatchResult, RuntimeError> {
        T::execute_batch(&**self, ctx, batch, in_msgs)
    }

    fn schedule_and_execute_batch(
        &self,
        ctx: Context,
        initial_batch: &mut TxnBatch,
        in_msgs: &[roothash::IncomingMessage],
    ) -> Result<ExecuteBatchResult, RuntimeError> {
        T::schedule_and_execute_batch(&**self, ctx, initial_batch, in_msgs)
    }

    fn check_batch(
        &self,
        ctx: Context,
        batch: &TxnBatch,
    ) -> Result<Vec<CheckTxResult>, RuntimeError> {
        T::check_batch(&**self, ctx, batch)
    }

    fn finalize(&self, new_storage_root: Hash) {
        T::finalize(&**self, new_storage_root)
    }

    fn set_abort_batch_flag(&mut self, abort_batch: Arc<AtomicBool>) {
        T::set_abort_batch_flag(&mut **self, abort_batch)
    }

    fn query(&self, ctx: Context, method: &str, args: Vec<u8>) -> Result<Vec<u8>, RuntimeError> {
        T::query(&**self, ctx, method, args)
    }
}

impl<T: Dispatcher + ?Sized> Dispatcher for Arc<T> {
    fn is_supported(&self) -> bool {
        T::is_supported(&**self)
    }

    fn execute_batch(
        &self,
        ctx: Context,
        batch: &TxnBatch,
        in_msgs: &[roothash::IncomingMessage],
    ) -> Result<ExecuteBatchResult, RuntimeError> {
        T::execute_batch(&**self, ctx, batch, in_msgs)
    }

    fn schedule_and_execute_batch(
        &self,
        ctx: Context,
        initial_batch: &mut TxnBatch,
        in_msgs: &[roothash::IncomingMessage],
    ) -> Result<ExecuteBatchResult, RuntimeError> {
        T::schedule_and_execute_batch(&**self, ctx, initial_batch, in_msgs)
    }

    fn check_batch(
        &self,
        ctx: Context,
        batch: &TxnBatch,
    ) -> Result<Vec<CheckTxResult>, RuntimeError> {
        T::check_batch(&**self, ctx, batch)
    }

    fn finalize(&self, new_storage_root: Hash) {
        T::finalize(&**self, new_storage_root)
    }

    fn set_abort_batch_flag(&mut self, _abort_batch: Arc<AtomicBool>) {
        unimplemented!()
    }

    fn query(&self, ctx: Context, method: &str, args: Vec<u8>) -> Result<Vec<u8>, RuntimeError> {
        T::query(&**self, ctx, method, args)
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
    /// Hashes of transactions to reject.
    ///
    /// Note that these are only taken into account in schedule execution mode.
    pub tx_reject_hashes: Vec<Hash>,
}

/// No-op dispatcher.
///
/// This is mainly used by the runtime dispatcher as a fallback in case
/// the runtime's initializer doesn't produce its own dispatcher object.
#[derive(Default)]
pub struct NoopDispatcher;

impl Dispatcher for NoopDispatcher {
    fn is_supported(&self) -> bool {
        false
    }

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
            in_msgs_count: in_msgs.len(),
            tx_reject_hashes: Vec::new(),
        })
    }

    fn schedule_and_execute_batch(
        &self,
        _ctx: Context,
        _initial_batch: &mut TxnBatch,
        in_msgs: &[roothash::IncomingMessage],
    ) -> Result<ExecuteBatchResult, RuntimeError> {
        Ok(ExecuteBatchResult {
            results: Vec::new(),
            messages: Vec::new(),
            block_tags: Tags::new(),
            in_msgs_count: in_msgs.len(),
            tx_reject_hashes: Vec::new(),
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
