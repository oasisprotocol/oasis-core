//! Client-facing service.
use std::sync::Arc;

use grpcio;
use grpcio::{RpcStatus, RpcStatusCode};

use ekiden_core::futures::Future;
use ekiden_rpc_api::{CallEnclaveRequest, CallEnclaveResponse, EnclaveRpc};

use super::super::worker::WorkerHost;

struct EnclaveRpcServiceInner {
    /// Worker.
    worker: Arc<WorkerHost>,
}

#[derive(Clone)]
pub struct EnclaveRpcService {
    inner: Arc<EnclaveRpcServiceInner>,
}

impl EnclaveRpcService {
    /// Create new compute server instance.
    pub fn new(worker: Arc<WorkerHost>) -> Self {
        EnclaveRpcService {
            inner: Arc::new(EnclaveRpcServiceInner { worker }),
        }
    }
}

impl EnclaveRpc for EnclaveRpcService {
    fn call_enclave(
        &self,
        ctx: grpcio::RpcContext,
        mut rpc_request: CallEnclaveRequest,
        sink: grpcio::UnarySink<CallEnclaveResponse>,
    ) {
        measure_histogram_timer!("call_enclave_time");
        measure_counter_inc!("call_enclave_calls");

        // TODO: Support routing to multiple enclaves based on enclave_id.

        // Send command to worker thread.
        let response_receiver = self.inner.worker.rpc_call(rpc_request.take_payload());

        // Prepare response future.
        let f = response_receiver.then(|result| match result {
            Ok(response) => {
                let mut rpc_response = CallEnclaveResponse::new();
                rpc_response.set_payload(response);

                sink.success(rpc_response)
            }
            Err(error) => sink.fail(RpcStatus::new(
                RpcStatusCode::Internal,
                Some(error.description().to_owned()),
            )),
        });
        ctx.spawn(f.map_err(|_error| ()));
    }
}
