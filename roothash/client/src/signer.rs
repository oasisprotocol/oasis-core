//! Signer for internal root hash backends (dummy, tendermint).
use std::sync::Arc;

use ekiden_common::error::Result;
use ekiden_common::identity::NodeIdentity;
use ekiden_roothash_base::{Commitment as OpaqueCommitment, Header, RootHashSigner};

use super::commitment::Commitment;

/// Signer for the root hash backend.
pub struct InternalRootHashSigner {
    identity: Arc<NodeIdentity>,
}

impl InternalRootHashSigner {
    pub fn new(identity: Arc<NodeIdentity>) -> Self {
        Self { identity }
    }
}

impl RootHashSigner for InternalRootHashSigner {
    fn sign_commitment(&self, header: &Header) -> Result<OpaqueCommitment> {
        let commitment = Commitment::new(&self.identity.get_node_signer(), header.clone());

        Ok(commitment.into())
    }
}

// Register for dependency injection.
create_component!(
    internal,
    "roothash-signer",
    InternalRootHashSigner,
    RootHashSigner,
    [NodeIdentity]
);
