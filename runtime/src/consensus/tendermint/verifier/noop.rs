use std::sync::Arc;

use anyhow::anyhow;
use io_context::Context;

use crate::{
    consensus::{
        beacon::EpochTime,
        roothash::{ComputeResultsHeader, Header},
        state::ConsensusState,
        tendermint::decode_light_block,
        verifier::{self, Error},
        Event, LightBlock, HEIGHT_LATEST,
    },
    protocol::Protocol,
    types::{Body, EventKind, HostFetchConsensusEventsRequest, HostFetchConsensusEventsResponse},
};

/// A verifier which performs no verification.
pub struct NopVerifier {
    protocol: Arc<Protocol>,
}

impl NopVerifier {
    /// Create a new non-verifying verifier.
    pub fn new(protocol: Arc<Protocol>) -> Self {
        Self { protocol }
    }

    fn fetch_light_block(&self, height: u64) -> Result<LightBlock, Error> {
        let result = self
            .protocol
            .call_host(
                Context::background(),
                Body::HostFetchConsensusBlockRequest { height },
            )
            .map_err(|err| Error::VerificationFailed(err.into()))?;

        match result {
            Body::HostFetchConsensusBlockResponse { block } => Ok(block),
            _ => Err(Error::VerificationFailed(anyhow!("bad response from host"))),
        }
    }
}

impl verifier::Verifier for NopVerifier {
    fn sync(&self, _height: u64) -> Result<(), Error> {
        Ok(())
    }

    fn verify(
        &self,
        consensus_block: LightBlock,
        _runtime_header: Header,
        _epoch: EpochTime,
    ) -> Result<ConsensusState, Error> {
        self.unverified_state(consensus_block)
    }

    fn verify_for_query(
        &self,
        consensus_block: LightBlock,
        _runtime_header: Header,
        _epoch: EpochTime,
    ) -> Result<ConsensusState, Error> {
        self.unverified_state(consensus_block)
    }

    fn unverified_state(&self, consensus_block: LightBlock) -> Result<ConsensusState, Error> {
        let untrusted_block =
            decode_light_block(consensus_block).map_err(Error::VerificationFailed)?;
        // NOTE: No actual verification is performed.
        let state_root = untrusted_block.get_state_root();
        Ok(ConsensusState::from_protocol(
            self.protocol.clone(),
            state_root.version + 1,
            state_root,
        ))
    }

    fn latest_state(&self) -> Result<ConsensusState, Error> {
        self.state_at(HEIGHT_LATEST)
    }

    fn state_at(&self, height: u64) -> Result<ConsensusState, Error> {
        let block = self.fetch_light_block(height)?;
        self.unverified_state(block)
    }

    fn events_at(&self, height: u64, kind: EventKind) -> Result<Vec<Event>, Error> {
        let result = self
            .protocol
            .call_host(
                Context::background(),
                Body::HostFetchConsensusEventsRequest(HostFetchConsensusEventsRequest {
                    height,
                    kind,
                }),
            )
            .map_err(|err| Error::VerificationFailed(err.into()))?;

        match result {
            Body::HostFetchConsensusEventsResponse(HostFetchConsensusEventsResponse { events }) => {
                Ok(events)
            }
            _ => Err(Error::VerificationFailed(anyhow!("bad response from host"))),
        }
    }

    fn latest_height(&self) -> Result<u64, Error> {
        Ok(self.fetch_light_block(HEIGHT_LATEST)?.height)
    }

    fn trust(&self, _header: &ComputeResultsHeader) -> Result<(), Error> {
        Ok(())
    }
}
