//! Inter-node service.
use std::convert::TryFrom;
use std::sync::Arc;

use grpcio;
use grpcio::{RpcStatus, RpcStatusCode};

use ekiden_compute_api::{ComputationGroup, SubmitAggCommitRequest, SubmitAggResponse,
                         SubmitAggRevealRequest, SubmitBatchRequest, SubmitBatchResponse};
use ekiden_core::bytes::H256;
use ekiden_core::error::Result;
use ekiden_core::futures::Future;
use ekiden_core::x509::get_node_id;

use super::super::consensus::ConsensusFrontend;
use ekiden_consensus_base::{Commitment, Reveal};

struct Inner {
    /// Consensus frontend.
    consensus_frontend: Arc<ConsensusFrontend>,
}

#[derive(Clone)]
pub struct ComputationGroupService {
    inner: Arc<Inner>,
}

impl ComputationGroupService {
    /// Create new computation group service.
    pub fn new(consensus_frontend: Arc<ConsensusFrontend>) -> Self {
        ComputationGroupService {
            inner: Arc::new(Inner { consensus_frontend }),
        }
    }
}

impl ComputationGroup for ComputationGroupService {
    fn submit_batch(
        &self,
        ctx: grpcio::RpcContext,
        request: SubmitBatchRequest,
        sink: grpcio::UnarySink<SubmitBatchResponse>,
    ) {
        measure_histogram_timer!("submit_batch_time");
        measure_counter_inc!("submit_batch_calls");

        let f = || -> Result<()> {
            let node_id = get_node_id(&ctx)?;
            let batch_hash = H256::try_from(request.get_batch_hash())?;

            self.inner
                .consensus_frontend
                .process_remote_batch(node_id, batch_hash)?;

            Ok(())
        };

        let f = match f() {
            Ok(()) => sink.success(SubmitBatchResponse::new()),
            Err(error) => sink.fail(RpcStatus::new(
                RpcStatusCode::Internal,
                Some(error.description().to_owned()),
            )),
        };
        ctx.spawn(f.map_err(|_error| ()));
    }

    fn submit_agg_commit(
        &self,
        ctx: grpcio::RpcContext,
        request: SubmitAggCommitRequest,
        sink: grpcio::UnarySink<SubmitAggResponse>,
    ) {
        measure_histogram_timer!("submit_agg_commit_time");
        measure_counter_inc!("submit_agg_commit_calls");

        let f = || -> Result<()> {
            let node_id = get_node_id(&ctx)?;
            let commitment = Commitment::try_from(request.get_commit().clone())?;

            self.inner
                .consensus_frontend
                .process_agg_commit(node_id, commitment)?;

            Ok(())
        };

        let f = match f() {
            Ok(()) => sink.success(SubmitAggResponse::new()),
            Err(error) => sink.fail(RpcStatus::new(
                RpcStatusCode::Internal,
                Some(error.description().to_owned()),
            )),
        };
        ctx.spawn(f.map_err(|_error| ()));
    }

    fn submit_agg_reveal(
        &self,
        ctx: grpcio::RpcContext,
        request: SubmitAggRevealRequest,
        sink: grpcio::UnarySink<SubmitAggResponse>,
    ) {
        measure_histogram_timer!("submit_agg_reveal_time");
        measure_counter_inc!("submit_agg_reveal_calls");

        let f = || -> Result<()> {
            let node_id = get_node_id(&ctx)?;
            let reveal = Reveal::try_from(request.get_reveal().clone())?;

            self.inner
                .consensus_frontend
                .process_agg_reveal(node_id, reveal)?;

            Ok(())
        };

        let f = match f() {
            Ok(()) => sink.success(SubmitAggResponse::new()),
            Err(error) => sink.fail(RpcStatus::new(
                RpcStatusCode::Internal,
                Some(error.description().to_owned()),
            )),
        };
        ctx.spawn(f.map_err(|_error| ()));
    }
}
