//! Commitment type used in the dummy backend.
use std::convert::TryFrom;

use serde_cbor;

use ekiden_common::bytes::{B256, B64};
use ekiden_common::error::{Error, Result};
use ekiden_common::signature::{Signed, Signer};
use ekiden_consensus_base::{Commitment as OpaqueCommitment, Header};

/// Signature context used for commitments.
const COMMITMENT_SIGNATURE_CONTEXT: B64 = B64(*b"EkCommit");

/// Commitment of a header
///
/// The signature on the commitment is made using the `COMMITMENT_SIGNATURE_CONTEXT`
/// context.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commitment(Signed<Header>);

impl Commitment {
    /// Generate a commitment.
    pub fn new(signer: &Signer, header: Header) -> Self {
        Commitment(Signed::sign(signer, &COMMITMENT_SIGNATURE_CONTEXT, header))
    }

    /// Verify signature and return signed header.
    pub fn open(&self) -> Result<Header> {
        self.0.open(&COMMITMENT_SIGNATURE_CONTEXT)
    }

    /// Return public key of commitment signer.
    pub fn get_public_key(&self) -> B256 {
        self.0.signature.public_key
    }
}

impl TryFrom<OpaqueCommitment> for Commitment {
    /// Converts an `OpaqueCommitment` into a `Commitment`.
    type Error = Error;

    fn try_from(other: OpaqueCommitment) -> Result<Self> {
        Ok(serde_cbor::from_slice(&other.data)?)
    }
}

impl Into<OpaqueCommitment> for Commitment {
    /// Converts a `Commitment` into an `OpaqueCommitment`.
    fn into(self) -> OpaqueCommitment {
        OpaqueCommitment {
            data: serde_cbor::to_vec(&self).unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use ekiden_common::bytes::B256;
    use ekiden_common::ring::signature::Ed25519KeyPair;
    use ekiden_common::signature::InMemorySigner;
    use ekiden_common::untrusted;
    use ekiden_consensus_base::Block;

    use super::*;

    #[test]
    fn test_block_commitment() {
        let block = Block::default();
        let key_pair =
            Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();
        let signer = InMemorySigner::new(key_pair);

        // Test commitment.
        let commitment = Commitment::new(&signer, block.header.clone());
        assert_eq!(commitment.get_public_key(), signer.get_public_key());
        let decoded_header = commitment.open().unwrap();
        assert!(block.header == decoded_header);
    }
}
