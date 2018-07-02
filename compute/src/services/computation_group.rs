//! Inter-node service.
use std::convert::TryFrom;
use std::sync::Arc;

use grpcio;
use grpcio::RpcStatus;

use ekiden_compute_api as api;
use ekiden_consensus_base::network::{Content, Message};
use ekiden_consensus_base::{Commitment, Reveal};
use ekiden_core::bytes::H256;
use ekiden_core::futures::prelude::*;
use ekiden_core::handle_rpc;
use ekiden_core::x509::get_node_id;

use super::super::consensus::ConsensusFrontend;
use super::super::group::ComputationGroup;

struct Inner {
    /// Consensus frontend.
    consensus_frontend: Arc<ConsensusFrontend>,
    /// Computation group.
    computation_group: Arc<ComputationGroup>,
}

#[derive(Clone)]
pub struct ComputationGroupService {
    inner: Arc<Inner>,
}

impl ComputationGroupService {
    /// Create new computation group service.
    pub fn new(
        consensus_frontend: Arc<ConsensusFrontend>,
        computation_group: Arc<ComputationGroup>,
    ) -> Self {
        ComputationGroupService {
            inner: Arc::new(Inner {
                consensus_frontend,
                computation_group,
            }),
        }
    }
}

impl api::ComputationGroup for ComputationGroupService {
    fn submit_batch(
        &self,
        ctx: grpcio::RpcContext,
        request: api::SubmitBatchRequest,
        sink: grpcio::UnarySink<api::SubmitBatchResponse>,
    ) {
        measure_histogram_timer!("submit_batch_time");
        measure_counter_inc!("submit_batch_calls");

        handle_rpc!(
            ctx,
            sink,
            {
                let node_id = get_node_id(&ctx)?;
                let batch_hash = H256::try_from(request.get_batch_hash())?;

                self.inner
                    .consensus_frontend
                    .process_remote_batch(node_id, batch_hash)?;

                Ok(())
            },
            api::SubmitBatchResponse::new()
        );
    }

    fn submit_agg_commit(
        &self,
        ctx: grpcio::RpcContext,
        request: api::SubmitAggCommitRequest,
        sink: grpcio::UnarySink<api::SubmitAggResponse>,
    ) {
        measure_histogram_timer!("submit_agg_commit_time");
        measure_counter_inc!("submit_agg_commit_calls");

        handle_rpc!(
            ctx,
            sink,
            {
                let node_id = get_node_id(&ctx)?;
                let commitment = Commitment::try_from(request.get_commit().clone())?;

                self.inner
                    .consensus_frontend
                    .process_agg_commit(node_id, commitment)?;

                Ok(())
            },
            api::SubmitAggResponse::new()
        );
    }

    fn submit_agg_reveal(
        &self,
        ctx: grpcio::RpcContext,
        request: api::SubmitAggRevealRequest,
        sink: grpcio::UnarySink<api::SubmitAggResponse>,
    ) {
        measure_histogram_timer!("submit_agg_reveal_time");
        measure_counter_inc!("submit_agg_reveal_calls");

        handle_rpc!(
            ctx,
            sink,
            {
                let node_id = get_node_id(&ctx)?;
                let reveal = Reveal::try_from(request.get_reveal().clone())?;

                self.inner
                    .consensus_frontend
                    .process_agg_reveal(node_id, reveal)?;

                Ok(())
            },
            api::SubmitAggResponse::new()
        );
    }

    fn consensus_gossip(
        &self,
        ctx: grpcio::RpcContext,
        request: api::ConsensusGossipRequest,
        sink: grpcio::UnarySink<api::ConsensusGossipResponse>,
    ) {
        measure_histogram_timer!("consensus_gossip_time");
        measure_counter_inc!("consensus_gossip_calls");

        handle_rpc!(
            ctx,
            sink,
            {
                let sender = get_node_id(&ctx)?;
                let content = Content::try_from(request.get_content().clone())?;

                self.inner
                    .computation_group
                    .deliver_incoming_consensus_gossip(Message { sender, content });

                Ok(())
            },
            api::ConsensusGossipResponse::new()
        );
    }
}
