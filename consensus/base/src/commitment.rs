//! Commitment type.
use std::convert::TryFrom;
use std::fmt::Debug;

use serde::Serialize;
use serde_cbor;

use ekiden_consensus_api as api;

use ekiden_common::bytes::{B256, B64, H256};
use ekiden_common::error::Error;
use ekiden_common::ring::digest;
use ekiden_common::signature::{Signature, Signer};

use super::header::Header;

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

impl TryFrom<api::Commitment> for Commitment {
    /// try_from Converts a protobuf commitment into a commitment.
    type Error = Error;
    fn try_from(a: api::Commitment) -> Result<Self, Error> {
        let sig = Signature::try_from(a.get_signature().to_owned())?;
        let digest = a.get_digest();
        Ok(Commitment {
            digest: H256::from(digest),
            signature: sig,
        })
    }
}

impl Into<api::Commitment> for Commitment {
    /// into Converts a block into a protobuf `consensus::api::Block` representation.
    fn into(self) -> api::Commitment {
        let mut c = api::Commitment::new();
        c.set_digest(self.digest.to_vec());
        c.set_signature(self.signature.into());
        c
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

impl TryFrom<api::Reveal> for Reveal<Header> {
    /// try_from Converts a protobuf reveal into a Reveal.
    type Error = Error;
    fn try_from(a: api::Reveal) -> Result<Self, Error> {
        let hdr = Header::try_from(a.get_header().to_owned())?;
        let non = B256::from(a.get_nonce());
        let sig = Signature::try_from(a.get_signature().to_owned())?;
        Ok(Reveal {
            value: hdr,
            nonce: non,
            signature: sig,
        })
    }
}

impl Into<api::Reveal> for Reveal<Header> {
    /// into Converts a reveal into a protobuf `consensus::api::Reveal` representation.
    fn into(self) -> api::Reveal {
        let mut c = api::Reveal::new();
        c.set_header(self.value.into());
        c.set_nonce(self.nonce.to_vec());
        c.set_signature(self.signature.into());
        c
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
