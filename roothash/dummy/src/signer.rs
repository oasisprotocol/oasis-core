//! Signer for the dummy root hash backend.
use std::sync::Arc;

use ekiden_common::error::Result;
use ekiden_common::identity::NodeIdentity;
use ekiden_roothash_base::{Commitment as OpaqueCommitment, Header, RootHashSigner};

use super::commitment::Commitment;

/// Signer for the dummy root hash backend.
pub struct DummyRootHashSigner {
    identity: Arc<NodeIdentity>,
}

impl DummyRootHashSigner {
    pub fn new(identity: Arc<NodeIdentity>) -> Self {
        Self { identity }
    }
}

impl RootHashSigner for DummyRootHashSigner {
    fn sign_commitment(&self, header: &Header) -> Result<OpaqueCommitment> {
        let commitment = Commitment::new(&self.identity.get_node_signer(), header.clone());

        Ok(commitment.into())
    }
}

// Register for dependency injection.
create_component!(
    dummy,
    "roothash-signer",
    DummyRootHashSigner,
    RootHashSigner,
    [NodeIdentity]
);
