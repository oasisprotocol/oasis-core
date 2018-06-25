//! Commitment/reveal types used in the dummy backend.
use std::convert::TryFrom;
use std::fmt::Debug;

use serde::Serialize;
use serde_cbor;

use ekiden_common::bytes::{B256, B64, H256};
use ekiden_common::error::{Error, Result};
use ekiden_common::ring::digest;
use ekiden_common::signature::{Signature, Signer};
use ekiden_consensus_base::{Commitment as OpaqueCommitment, Header, Reveal as OpaqueReveal};

/// Signature context used for commitments.
const COMMITMENT_SIGNATURE_CONTEXT: B64 = B64(*b"EkCommit");
/// Signature context used for reveals.
const REVEAL_SIGNATURE_CONTEXT: B64 = B64(*b"EkReveal");

/// Commitment.
///
/// A commitment is a signature over a specific piece of data using the
/// `COMMITMENT_SIGNATURE_CONTEXT` context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    /// Hash of the encoded value being committed to and a nonce.
    pub digest: H256,
    /// Commitment signature over the digest.
    pub signature: Signature,
}

impl Commitment {
    /// Construct a new commitment.
    pub fn new<T: Commitable>(signer: &Signer, nonce: &B256, value: &T) -> Self {
        let digest = value.get_commitment_digest(&nonce);

        Commitment {
            digest,
            signature: Signature::sign(signer, &COMMITMENT_SIGNATURE_CONTEXT, &digest),
        }
    }

    /// Verify that the commitment has a valid signature.
    pub fn verify(&self) -> bool {
        self.signature
            .verify(&COMMITMENT_SIGNATURE_CONTEXT, &self.digest)
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

/// Reveal.
///
/// A reveal of a value previously committed to. The signature on the reveal
/// is made using the `REVEAL_SIGNATURE_CONTEXT` context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reveal<T: Commitable> {
    /// Revealed value.
    pub value: T,
    /// Nonce used in commitment.
    pub nonce: B256,
    /// Signature over `value` and `nonce`.
    pub signature: Signature,
}

impl<T: Commitable> Reveal<T> {
    /// Generate a reveal for a commitable value.
    pub fn new(signer: &Signer, nonce: &B256, value: &T) -> Self {
        let digest = value.get_commitment_digest(nonce);

        Reveal {
            value: value.clone(),
            nonce: nonce.clone(),
            signature: Signature::sign(signer, &REVEAL_SIGNATURE_CONTEXT, &digest),
        }
    }

    /// Verify that the reveal has a valid signature.
    pub fn verify(&self) -> bool {
        let digest = self.value.get_commitment_digest(&self.nonce);

        self.signature.verify(&REVEAL_SIGNATURE_CONTEXT, &digest)
    }

    /// Verify that the reveal matches commitment.
    pub fn verify_commitment(&self, commitment: &Commitment) -> bool {
        // Verify that both signatures were made using the same public key.
        if self.signature.public_key != commitment.signature.public_key {
            return false;
        }

        // Verify reveal signature.
        if !self.verify() {
            return false;
        }

        // Verify commitment signature.
        if !commitment.verify() {
            return false;
        }

        // Verify that value matches commitment.
        let digest = self.value.get_commitment_digest(&self.nonce);

        digest == commitment.digest
    }

    /// Verify that the reveal matches value.
    pub fn verify_value(&self, value: &T) -> bool {
        // Verify reveal signature.
        if !self.verify() {
            return false;
        }

        // Verify that reveal matches given value.
        let reveal_digest = self.value.get_commitment_digest(&self.nonce);
        let value_digest = value.get_commitment_digest(&self.nonce);

        reveal_digest == value_digest
    }
}

impl TryFrom<OpaqueReveal> for Reveal<Header> {
    /// Converts an `OpaqueReveal` into a `Reveal<Header>`.
    type Error = Error;

    fn try_from(other: OpaqueReveal) -> Result<Self> {
        Ok(serde_cbor::from_slice(&other.data)?)
    }
}

impl Into<OpaqueReveal> for Reveal<Header> {
    /// Converts a `Reveal<Header>` into an `OpaqueReveal`.
    fn into(self) -> OpaqueReveal {
        OpaqueReveal {
            data: serde_cbor::to_vec(&self).unwrap(),
        }
    }
}

/// A type that a commitment can be generated for.
pub trait Commitable: Sized + Clone + Debug + PartialEq + Eq + Serialize {
    /// Return hash over nonce and commitment value.
    fn get_commitment_digest(&self, nonce: &B256) -> H256 {
        let mut ctx = digest::Context::new(&digest::SHA512_256);
        ctx.update(&serde_cbor::to_vec(self).unwrap());
        ctx.update(&nonce);
        H256::from(ctx.finish().as_ref())
    }
}

impl Commitable for Header {}

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
        let nonce = B256::zero();
        let key_pair =
            Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();
        let signer = InMemorySigner::new(key_pair);

        let header = block.header.clone();

        // Test commitment.
        let commitment = Commitment::new(&signer, &nonce, &header);
        assert!(commitment.verify());

        // Test reveal.
        let reveal = Reveal::new(&signer, &nonce, &header);
        assert!(reveal.verify());
        assert!(reveal.verify_commitment(&commitment));
        assert!(reveal.verify_value(&header));
    }
}
