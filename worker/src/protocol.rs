//! Protocol handler for worker RPCs.
use std::sync::{Condvar, Mutex};

use rustracing_jaeger::Span;

use ekiden_core::bytes::B256;
use ekiden_core::futures::prelude::*;
use ekiden_core::runtime::batch::CallBatch;
use ekiden_roothash_base::Block;
use ekiden_worker_api;
use ekiden_worker_api::types::ComputedBatch;

use super::worker::Worker;

/// Worker protocol handler.
pub struct ProtocolHandler {
    /// Worker handle.
    worker: Mutex<Option<Worker>>,
    worker_cond: Condvar,
}

impl ProtocolHandler {
    /// Create new protocol handler instance.
    pub fn new() -> Self {
        Self {
            worker: Mutex::new(None),
            worker_cond: Condvar::new(),
        }
    }

    /// Set worker thread to use for dispatching calls.
    pub fn set_worker(&self, worker: Worker) {
        let mut guard = self.worker.lock().unwrap();
        *guard = Some(worker);
        self.worker_cond.notify_all();
    }

    fn with_worker<F: FnOnce(&Worker) -> R, R>(&self, f: F) -> R {
        let mut guard = self.worker.lock().unwrap();
        while guard.is_none() {
            guard = self.worker_cond.wait(guard).unwrap();
        }
        let worker = guard.as_ref().expect("worker must be set");

        f(worker)
    }
}

impl ekiden_worker_api::Worker for ProtocolHandler {
    fn worker_shutdown(&self) -> BoxFuture<()> {
        unimplemented!();
    }

    fn capabilitytee_gid(&self) -> BoxFuture<[u8; 4]> {
        self.with_worker(|worker| worker.capabilitytee_gid())
    }

    fn capabilitytee_rak_quote(
        &self,
        quote_type: u32,
        spid: [u8; 16],
        sig_rl: Vec<u8>,
    ) -> BoxFuture<(B256, Vec<u8>)> {
        self.with_worker(|worker| worker.capabilitytee_rak_quote(quote_type, spid, sig_rl))
    }

    fn rpc_call(&self, request: Vec<u8>) -> BoxFuture<Vec<u8>> {
        self.with_worker(|worker| worker.rpc_call(request))
    }

    fn runtime_call_batch(
        &self,
        calls: CallBatch,
        block: Block,
        commit_storage: bool,
    ) -> BoxFuture<ComputedBatch> {
        // TODO: Correlate to an event source
        let sh = Span::inactive().handle();

        self.with_worker(|worker| worker.runtime_call_batch(calls, block, sh, commit_storage))
    }
}
