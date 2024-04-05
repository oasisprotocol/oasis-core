//! Verified consensus state for registry application.
use std::sync::Arc;

use anyhow::Result;

use oasis_core_runtime::{
    common::{crypto::signature::PublicKey, namespace::Namespace},
    consensus::{state::registry::ImmutableState as RegistryState, verifier::Verifier},
    future::block_on,
};

/// Verified consensus state for registry application.
pub struct State {
    consensus_verifier: Arc<dyn Verifier>,
}

impl State {
    /// Creates a new registry state.
    pub fn new(consensus_verifier: Arc<dyn Verifier>) -> Self {
        Self { consensus_verifier }
    }

    /// Returns runtime attestation key of the given node.
    pub fn rak(&self, node_id: &PublicKey, runtime_id: &Namespace) -> Result<Option<PublicKey>> {
        let consensus_state = block_on(self.consensus_verifier.latest_state())?;
        let registry_state = RegistryState::new(&consensus_state);

        let node = registry_state.node(node_id)?;
        let node = match node {
            None => return Ok(None),
            Some(node) => node,
        };

        // Skipping version check as key managers are running exactly
        // one version of the runtime.
        let runtimes = node.runtimes.unwrap_or_default();
        let runtime = runtimes.iter().find(|nr| &nr.id == runtime_id);
        let runtime = match runtime {
            None => return Ok(None),
            Some(runtime) => runtime,
        };

        let tee = match &runtime.capabilities.tee {
            None => return Ok(None),
            Some(tee) => tee,
        };

        Ok(Some(tee.rak))
    }
}
