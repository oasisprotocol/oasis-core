//! Signer for the dummy consensus backend.
use std::sync::Arc;

use ekiden_common::error::Result;
use ekiden_common::identity::NodeIdentity;
use ekiden_consensus_base::{Commitment as OpaqueCommitment, ConsensusSigner, Header};

use super::commitment::Commitment;

/// Signer for the dummy consensus backend.
pub struct DummyConsensusSigner {
    identity: Arc<NodeIdentity>,
}

impl DummyConsensusSigner {
    pub fn new(identity: Arc<NodeIdentity>) -> Self {
        Self { identity }
    }
}

impl ConsensusSigner for DummyConsensusSigner {
    fn sign_commitment(&self, header: &Header) -> Result<OpaqueCommitment> {
        let commitment = Commitment::new(&self.identity.get_node_signer(), header.clone());

        Ok(commitment.into())
    }
}

// Register for dependency injection.
create_component!(
    dummy,
    "consensus-signer",
    DummyConsensusSigner,
    ConsensusSigner,
    [NodeIdentity]
);
