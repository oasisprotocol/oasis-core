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
use ekiden_core::signature::{Signature, Signed};

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
        mut request: SubmitBatchRequest,
        sink: grpcio::UnarySink<SubmitBatchResponse>,
    ) {
        measure_histogram_timer!("submit_batch_time");
        measure_counter_inc!("submit_batch_calls");

        let mut f = || -> Result<()> {
            let batch_hash = H256::try_from(request.get_batch_hash())?;
            let signature = Signature::try_from(request.take_signature())?;
            let signed_batch = Signed::from_parts(batch_hash, signature);

            self.inner
                .consensus_frontend
                .process_remote_batch(signed_batch)?;

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
        mut request: SubmitAggCommitRequest,
        sink: grpcio::UnarySink<SubmitAggResponse>,
    ) {
        measure_histogram_timer!("submit_agg_commit_time");
        measure_counter_inc!("submit_agg_commit_calls");

        let mut f = || -> Result<()> {
            let commit = Commitment::try_from(request.get_commit().clone())?;
            let signature = Signature::try_from(request.take_signature())?;
            let signed_commit = Signed::from_parts(commit, signature);

            self.inner
                .consensus_frontend
                .process_agg_commit(signed_commit)?;

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
        mut request: SubmitAggRevealRequest,
        sink: grpcio::UnarySink<SubmitAggResponse>,
    ) {
        measure_histogram_timer!("submit_agg_reveal_time");
        measure_counter_inc!("submit_agg_reveal_calls");

        let mut f = || -> Result<()> {
            let reveal = Reveal::try_from(request.get_reveal().clone())?;
            let signature = Signature::try_from(request.take_signature())?;
            let signed_reveal = Signed::from_parts(reveal, signature);

            self.inner
                .consensus_frontend
                .process_agg_reveal(signed_reveal)?;

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
