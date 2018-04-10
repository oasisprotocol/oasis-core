//! Commitment type.
use std;
use std::fmt::Debug;

use ekiden_common::bytes::{B256, B64, H256};
use ekiden_common::ring::digest;
use ekiden_common::rlp::{self, Decodable, DecoderError, Encodable, RlpStream, UntrustedRlp};
use ekiden_common::signature::{Signature, Signer, Verifier};

/// Signature context used for commitments.
const COMMITMENT_SIGNATURE_CONTEXT: B64 = B64(*b"EkCommit");
/// Signature context used for reveals.
const REVEAL_SIGNATURE_CONTEXT: B64 = B64(*b"EkReveal");

/// Commitment.
///
/// A commitment is a signature over a specific piece of data using the
/// `COMMITMENT_SIGNATURE_CONTEXT` context.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    pub fn verify(&self, verifier: &Verifier) -> bool {
        self.signature
            .verify(verifier, &COMMITMENT_SIGNATURE_CONTEXT, &self.digest)
    }
}

impl Encodable for Commitment {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(3);
        stream.append(&self.digest);
        stream.append(&self.signature);
    }
}

impl Decodable for Commitment {
    fn decode(rlp: &UntrustedRlp) -> std::result::Result<Self, DecoderError> {
        Ok(Self {
            digest: rlp.val_at(0)?,
            signature: rlp.val_at(1)?,
        })
    }
}

/// Reveal.
///
/// A reveal of a value previously committed to. The signature on the reveal
/// is made using the `REVEAL_SIGNATURE_CONTEXT` context.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    pub fn verify(&self, verifier: &Verifier) -> bool {
        let digest = self.value.get_commitment_digest(&self.nonce);

        self.signature
            .verify(verifier, &REVEAL_SIGNATURE_CONTEXT, &digest)
    }

    /// Verify that the reveal matches commitment.
    pub fn verify_commitment(&self, verifier: &Verifier, commitment: &Commitment) -> bool {
        // Verify reveal signature.
        if !self.verify(verifier) {
            return false;
        }

        // Verify commitment signature.
        if !commitment.verify(verifier) {
            return false;
        }

        // Verify that value matches commitment.
        let digest = self.value.get_commitment_digest(&self.nonce);

        digest == commitment.digest
    }

    /// Verify that the reveal matches value.
    pub fn verify_value(&self, verifier: &Verifier, value: &T) -> bool {
        // Verify reveal signature.
        if !self.verify(verifier) {
            return false;
        }

        // Verify that reveal matches given value.
        let reveal_digest = self.value.get_commitment_digest(&self.nonce);
        let value_digest = value.get_commitment_digest(&self.nonce);

        reveal_digest == value_digest
    }
}

impl<T: Commitable> Encodable for Reveal<T> {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(3);
        stream.append(&self.value);
        stream.append(&self.nonce);
        stream.append(&self.signature);
    }
}

impl<T: Commitable> Decodable for Reveal<T> {
    fn decode(rlp: &UntrustedRlp) -> std::result::Result<Self, DecoderError> {
        Ok(Self {
            value: rlp.val_at(0)?,
            nonce: rlp.val_at(1)?,
            signature: rlp.val_at(2)?,
        })
    }
}

/// A type that a commitment can be generated for.
pub trait Commitable
    : Sized + Clone + Debug + PartialEq + Eq + Encodable + Decodable {
    /// Return hash over nonce and commitment value.
    fn get_commitment_digest(&self, nonce: &B256) -> H256 {
        let mut ctx = digest::Context::new(&digest::SHA512_256);
        ctx.update(&rlp::encode(self));
        ctx.update(&nonce);
        H256::from(ctx.finish().as_ref())
    }
}
