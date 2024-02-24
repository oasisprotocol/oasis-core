//! Verified consensus state for CHURP extension.
use std::sync::Arc;

use anyhow::Result;

use oasis_core_runtime::{
    common::namespace::Namespace,
    consensus::{
        state::keymanager::churp::{ImmutableState as ChurpState, Status},
        verifier::Verifier as ConsensusVerifier,
    },
    future::block_on,
};

use super::Error;

/// Verified consensus state for CHURP extension.
pub struct State {
    consensus_verifier: Arc<dyn ConsensusVerifier>,
}

impl State {
    /// Creates a new CHURP state.
    pub fn new(consensus_verifier: Arc<dyn ConsensusVerifier>) -> Self {
        Self { consensus_verifier }
    }

    /// Returns the latest CHURP status.
    pub fn status(&self, runtime_id: Namespace, churp_id: u8) -> Result<Status> {
        let consensus_state = block_on(self.consensus_verifier.latest_state())?;
        let churp_state = ChurpState::new(&consensus_state);
        let status = churp_state
            .status(runtime_id, churp_id)?
            .ok_or(Error::StatusNotPublished)?;

        Ok(status)
    }
}
