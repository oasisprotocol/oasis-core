//! Inter-node service.
use std::convert::TryFrom;
use std::sync::Arc;

use grpcio;
use grpcio::{RpcStatus, RpcStatusCode};

use ekiden_compute_api::{ComputationGroup, SubmitBatchRequest, SubmitBatchResponse};
use ekiden_core::bytes::H256;
use ekiden_core::error::Result;
use ekiden_core::futures::Future;
use ekiden_core::header::Header;
use ekiden_core::x509::get_node_id;

use super::super::roothash::RootHashFrontend;

struct Inner {
    /// Root hash frontend.
    roothash_frontend: Arc<RootHashFrontend>,
}

#[derive(Clone)]
pub struct ComputationGroupService {
    inner: Arc<Inner>,
}

impl ComputationGroupService {
    /// Create new computation group service.
    pub fn new(roothash_frontend: Arc<RootHashFrontend>) -> Self {
        ComputationGroupService {
            inner: Arc::new(Inner { roothash_frontend }),
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
            let block_header = Header::try_from(request.get_block_header().clone())?;
            let group_hash = H256::try_from(request.get_group_hash())?;

            self.inner.roothash_frontend.process_remote_batch(
                node_id,
                batch_hash,
                block_header,
                group_hash,
            )?;

            Ok(())
        };

        let f = match f() {
            Ok(()) => sink.success(SubmitBatchResponse::new()),
            Err(error) => sink.fail(RpcStatus::new(
                RpcStatusCode::Unavailable,
                Some(error.description().to_owned()),
            )),
        };
        ctx.spawn(f.map_err(|_error| ()));
    }
}
