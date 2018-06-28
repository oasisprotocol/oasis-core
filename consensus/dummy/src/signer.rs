//! Signer for the dummy consensus backend.
use std::sync::Arc;

use ekiden_common::bytes::B256;
use ekiden_common::error::Result;
use ekiden_common::identity::NodeIdentity;
use ekiden_consensus_base::{Commitment as OpaqueCommitment, ConsensusSigner, Header, Nonce,
                            Reveal as OpaqueReveal};

use super::commitment::{Commitment, Reveal};

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
    fn sign_commitment(&self, header: &Header) -> Result<(OpaqueCommitment, Nonce)> {
        let nonce = B256::random();
        let commitment = Commitment::new(&self.identity.get_node_signer(), &nonce, header);

        Ok((
            commitment.into(),
            Nonce {
                data: nonce.to_vec(),
            },
        ))
    }

    fn sign_reveal(&self, header: &Header, nonce: &Nonce) -> Result<OpaqueReveal> {
        let reveal = Reveal::new(
            &self.identity.get_node_signer(),
            &B256::from(&nonce.data[..]),
            header,
        );

        Ok(reveal.into())
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
