//! Verified consensus state for beacon application.
use std::sync::Arc;

use anyhow::Result;

use oasis_core_runtime::{
    consensus::{
        beacon::EpochTime, state::beacon::ImmutableState as BeaconState, verifier::Verifier,
    },
    future::block_on,
};

/// Verified consensus state for beacon application.
pub struct State {
    consensus_verifier: Arc<dyn Verifier>,
}

impl State {
    /// Creates a new beacon state.
    pub fn new(consensus_verifier: Arc<dyn Verifier>) -> Self {
        Self { consensus_verifier }
    }

    /// Returns the current epoch.
    pub fn epoch(&self) -> Result<EpochTime> {
        let consensus_state = block_on(self.consensus_verifier.latest_state())?;
        let beacon_state = BeaconState::new(&consensus_state);
        let epoch = beacon_state.epoch()?;

        Ok(epoch)
    }
}
