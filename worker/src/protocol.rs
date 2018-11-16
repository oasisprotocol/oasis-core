//! Protocol handler for worker RPCs.
use std::sync::RwLock;

use rustracing_jaeger::Span;

use ekiden_core::futures::prelude::*;
use ekiden_core::runtime::batch::CallBatch;
use ekiden_roothash_base::Block;
use ekiden_worker_api;
use ekiden_worker_api::types::ComputedBatch;

use super::worker::Worker;

/// Worker protocol handler.
pub struct ProtocolHandler {
    /// Worker handle.
    worker: RwLock<Option<Worker>>,
}

impl ProtocolHandler {
    /// Create new protocol handler instance.
    pub fn new() -> Self {
        Self {
            worker: RwLock::new(None),
        }
    }

    /// Set worker thread to use for dispatching calls.
    pub fn set_worker(&self, worker: Worker) {
        let mut guard = self.worker.write().unwrap();
        *guard = Some(worker);
    }
}

impl ekiden_worker_api::Worker for ProtocolHandler {
    fn worker_shutdown(&self) -> BoxFuture<()> {
        unimplemented!();
    }

    fn rpc_call(&self, request: Vec<u8>) -> BoxFuture<Vec<u8>> {
        let guard = self.worker.read().unwrap();
        let worker = guard.as_ref().expect("worker must be set");

        worker.rpc_call(request)
    }

    fn runtime_call_batch(
        &self,
        calls: CallBatch,
        block: Block,
        commit_storage: bool,
    ) -> BoxFuture<ComputedBatch> {
        let guard = self.worker.read().unwrap();
        let worker = guard.as_ref().expect("worker must be set");

        // TODO: Correlate to an event source
        let sh = Span::inactive().handle();

        worker.runtime_call_batch(calls, block, sh, commit_storage)
    }
}
