//! Contract call processing service.
use std::sync::Arc;

use grpcio;
use grpcio::{RpcStatus, RpcStatusCode};

use ekiden_compute_api::{Contract, SubmitTxRequest, SubmitTxResponse};
use ekiden_core::contract::batch::CallBatch;
use ekiden_core::futures::prelude::*;

use super::super::roothash::RootHashFrontend;

struct ContractServiceInner {
    /// Root hash frontend.
    roothash_frontend: Arc<RootHashFrontend>,
}

#[derive(Clone)]
pub struct ContractService {
    inner: Arc<ContractServiceInner>,
}

impl ContractService {
    /// Create new compute server instance.
    pub fn new(roothash_frontend: Arc<RootHashFrontend>) -> Self {
        ContractService {
            inner: Arc::new(ContractServiceInner { roothash_frontend }),
        }
    }
}

impl Contract for ContractService {
    fn submit_tx(
        &self,
        ctx: grpcio::RpcContext,
        mut request: SubmitTxRequest,
        sink: grpcio::UnarySink<SubmitTxResponse>,
    ) {
        measure_histogram_timer!("submit_tx_time");
        measure_counter_inc!("submit_tx_calls");

        let batch = CallBatch(vec![request.take_data()]);

        let result = match self.inner.roothash_frontend.append_batch(batch) {
            Ok(()) => sink.success(SubmitTxResponse::new()),
            Err(error) => sink.fail(RpcStatus::new(
                RpcStatusCode::Unavailable,
                Some(error.description().to_owned()),
            )),
        };

        ctx.spawn(result.map_err(|_error| ()));
    }
}
