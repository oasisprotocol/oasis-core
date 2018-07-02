//! Signer for the dummy consensus backend.
use std::convert::TryFrom;
use std::sync::Arc;

use ekiden_common::bytes::B256;
use ekiden_common::error::Error;
use ekiden_common::futures::prelude::*;
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
    fn sign_commitment(&self, header: &Header) -> BoxFuture<(OpaqueCommitment, Nonce)> {
        let nonce = B256::random();
        let commitment = Commitment::new(&self.identity.get_node_signer(), &nonce, header);

        future::ok((
            commitment.into(),
            Nonce {
                data: nonce.to_vec(),
            },
        )).into_box()
    }

    fn sign_reveal(&self, header: &Header, nonce: &Nonce) -> BoxFuture<OpaqueReveal> {
        let reveal = Reveal::new(
            &self.identity.get_node_signer(),
            &B256::from(&nonce.data[..]),
            header,
        );

        future::ok(reveal.into()).into_box()
    }

    fn verify_reveal(
        &self,
        node_id: B256,
        header: &Header,
        reveal: &OpaqueReveal,
    ) -> BoxFuture<()> {
        let reveal: Reveal<Header> = match Reveal::try_from(reveal.clone()) {
            Ok(reveal) => reveal,
            _ => return future::err(Error::new("reveal decoding failed")).into_box(),
        };

        if !reveal.verify_value(header) || reveal.signature.public_key != node_id {
            return future::err(Error::new("reveal verification failed")).into_box();
        }

        future::ok(()).into_box()
    }

    fn get_reveal_header(&self, reveal: &OpaqueReveal) -> BoxFuture<Header> {
        let reveal: Reveal<Header> = match Reveal::try_from(reveal.clone()) {
            Ok(reveal) => reveal,
            _ => return future::err(Error::new("reveal decoding failed")).into_box(),
        };

        future::ok(reveal.value).into_box()
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
