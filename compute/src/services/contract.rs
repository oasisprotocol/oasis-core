//! Contract call processing service.
use std::sync::Arc;

use grpcio;
use grpcio::{RpcStatus, RpcStatusCode};
use rustracing::tag;
use rustracing_jaeger::span::SpanContext;

use ekiden_compute_api::{Contract, SubmitTxRequest, SubmitTxResponse};
use ekiden_core::futures::prelude::*;
use ekiden_tracing;
use ekiden_tracing::MetadataCarrier;

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
        let tracer = ekiden_tracing::get_tracer();
        let mut sso = tracer
            .span("submit_tx")
            .tag(tag::StdTag::span_kind("server"));
        match SpanContext::extract_from_http_header(&MetadataCarrier(ctx.request_headers())) {
            Ok(Some(sc)) => {
                sso = sso.child_of(&sc);
            }
            Ok(None) => {}
            Err(error) => {
                error!(
                    "Tracing provider unable to extract span context: {:?}",
                    error
                );
            }
        }
        let submit_span = sso.start();

        let data = request.take_data();
        let append_span = submit_span.handle().child("append_batch", |sso| {
            sso.tag(tag::StdTag::span_kind("producer")).start()
        });

        let result = match self.inner
            .roothash_frontend
            .append_batch(data, append_span.context().cloned())
        {
            Ok(()) => sink.success(SubmitTxResponse::new()),
            Err(error) => sink.fail(RpcStatus::new(
                RpcStatusCode::Unavailable,
                Some(error.description().to_owned()),
            )),
        };

        ctx.spawn(result.map_err(|_error| ()));
    }
}
