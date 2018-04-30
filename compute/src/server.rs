use std::error::Error;
use std::sync::Arc;
use std::sync::mpsc::Sender;

use grpcio;
use grpcio::{RpcStatus, RpcStatusCode};
use thread_local::ThreadLocal;

use ekiden_compute_api::{CallContractRequest, CallContractResponse, Compute,
                         WaitContractCallRequest, WaitContractCallResponse};
use ekiden_core::bytes::H256;
use ekiden_core::futures::Future;
use ekiden_core::futures::sync::oneshot;

use super::instrumentation;
use super::worker::{Command, Worker};

struct ComputeServiceInner {
    /// Worker.
    worker: Arc<Worker>,
    /// Thread-local channel for submitting commands to the worker.
    tl_command_sender: ThreadLocal<Sender<Command>>,
    /// Instrumentation objects.
    ins: instrumentation::HandlerMetrics,
}

#[derive(Clone)]
pub struct ComputeService {
    inner: Arc<ComputeServiceInner>,
}

impl ComputeService {
    /// Create new compute server instance.
    pub fn new(worker: Arc<Worker>) -> Self {
        ComputeService {
            inner: Arc::new(ComputeServiceInner {
                worker,
                tl_command_sender: ThreadLocal::new(),
                ins: instrumentation::HandlerMetrics::new(),
            }),
        }
    }

    /// Get thread-local command sender.
    fn get_command_sender(&self) -> &Sender<Command> {
        self.inner
            .tl_command_sender
            .get_or(|| Box::new(self.inner.worker.get_command_sender()))
    }
}

impl Compute for ComputeService {
    fn call_contract(
        &self,
        ctx: grpcio::RpcContext,
        mut rpc_request: CallContractRequest,
        sink: grpcio::UnarySink<CallContractResponse>,
    ) {
        // Instrumentation.
        self.inner.ins.reqs_received.inc();
        let _client_timer = self.inner.ins.req_time_client.start_timer();

        // Send command to worker thread.
        let (response_sender, response_receiver) = oneshot::channel();
        self.get_command_sender()
            .send(Command::RpcCall(
                rpc_request.take_payload(),
                response_sender,
            ))
            .unwrap();

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

    fn wait_contract_call(
        &self,
        ctx: grpcio::RpcContext,
        request: WaitContractCallRequest,
        sink: grpcio::UnarySink<WaitContractCallResponse>,
    ) {
        let call_id = request.get_call_id();
        if call_id.len() != H256::LENGTH {
            ctx.spawn(
                sink.fail(RpcStatus::new(RpcStatusCode::InvalidArgument, None))
                    .map_err(|_error| ()),
            );
            return;
        }

        // Send command to worker thread.
        let (response_sender, response_receiver) = oneshot::channel();
        self.get_command_sender()
            .send(Command::SubscribeCall(
                H256::from(request.get_call_id()),
                response_sender,
            ))
            .unwrap();

        // Prepare response future.
        let f = response_receiver.then(|result| match result {
            Ok(Ok(response)) => {
                let mut rpc_response = WaitContractCallResponse::new();
                rpc_response.set_output(response);

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
