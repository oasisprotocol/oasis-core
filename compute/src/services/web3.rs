//! Client-facing service.
use std::error::Error;
use std::sync::Arc;

use grpcio;
use grpcio::{RpcStatus, RpcStatusCode};

use ekiden_compute_api::{CallContractRequest, CallContractResponse, Web3};
use ekiden_core::futures::Future;

use super::super::consensus::ConsensusFrontend;
use super::super::worker::Worker;

struct Web3ServiceInner {
    /// Worker.
    worker: Arc<Worker>,
    /// Consensus frontend.
    consensus_frontend: Arc<ConsensusFrontend>,
}

#[derive(Clone)]
pub struct Web3Service {
    inner: Arc<Web3ServiceInner>,
}

impl Web3Service {
    /// Create new compute server instance.
    pub fn new(worker: Arc<Worker>, consensus_frontend: Arc<ConsensusFrontend>) -> Self {
        Web3Service {
            inner: Arc::new(Web3ServiceInner {
                worker,
                consensus_frontend,
            }),
        }
    }
}

impl Web3 for Web3Service {
    fn call_contract(
        &self,
        ctx: grpcio::RpcContext,
        mut rpc_request: CallContractRequest,
        sink: grpcio::UnarySink<CallContractResponse>,
    ) {
        measure_histogram_timer!("call_contract_time");
        measure_counter_inc!("call_contract_calls");

        // Send command to worker thread and request any generated batches to be handled
        // by our consensus frontend.
        let response_receiver = self.inner.worker.rpc_call(
            rpc_request.take_payload(),
            self.inner.consensus_frontend.clone(),
        );

        // Prepare response future.
        let f = response_receiver.then(|result| match result {
            Ok(Ok(response)) => {
                let mut rpc_response = CallContractResponse::new();
                rpc_response.set_payload(response);

                sink.success(rpc_response)
            }
            Ok(Err(error)) => sink.fail(RpcStatus::new(
                RpcStatusCode::Internal,
                Some(error.description().to_owned()),
            )),
            Err(error) => sink.fail(RpcStatus::new(
                RpcStatusCode::Internal,
                Some(error.description().to_owned()),
            )),
        });
        ctx.spawn(f.map_err(|_error| ()));
    }
}
