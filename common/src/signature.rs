//! Signature interface.
use std;
use std::fmt::Debug;

use super::bytes::{B256, B512, B64, H256};
use super::error::{Error, Result};
use super::ring::{digest, signature};
use super::rlp::{self, Decodable, DecoderError, Encodable, RlpStream, UntrustedRlp};
use super::untrusted;

/// Signer interface.
pub trait Signer {
    /// Sign given 256-bit digest.
    fn sign(&self, data: &H256) -> B512;

    /// Get hash of the signing public key.
    fn get_public_key_id(&self) -> H256;

    /// Attest to given 256-bit digest.
    fn attest(&self, data: &H256) -> Option<Vec<u8>>;
}

/// Verifier interface.
pub trait Verifier {
    /// Verify signature and optional attestation.
    fn verify(&self, data: &H256, signature: &B512, attestation: Option<&Vec<u8>>) -> bool;
}

/// In memory signer.
pub struct InMemorySigner {
    /// Ed25519 key pair.
    key_pair: signature::Ed25519KeyPair,
}

impl InMemorySigner {
    /// Construct new in memory key pair.
    pub fn new(key_pair: signature::Ed25519KeyPair) -> Self {
        Self { key_pair }
    }
}

impl Signer for InMemorySigner {
    fn sign(&self, data: &H256) -> B512 {
        B512::from(self.key_pair.sign(data).as_ref())
    }

    fn get_public_key_id(&self) -> H256 {
        H256::from(digest::digest(&digest::SHA512_256, &self.key_pair.public_key_bytes()).as_ref())
    }

    fn attest(&self, _data: &H256) -> Option<Vec<u8>> {
        None
    }
}

/// Public key verifier.
pub struct PublicKeyVerifier {
    /// Public key.
    public_key: B256,
}

impl PublicKeyVerifier {
    pub fn new(public_key: B256) -> Self {
        Self { public_key }
    }
}

impl Verifier for PublicKeyVerifier {
    fn verify(&self, data: &H256, signature: &B512, attestation: Option<&Vec<u8>>) -> bool {
        // TODO: Verify attestation.
        match attestation {
            Some(_) => return false,
            None => {}
        }

        signature::verify(
            &signature::ED25519,
            untrusted::Input::from(&self.public_key),
            untrusted::Input::from(&data),
            untrusted::Input::from(&signature),
        ).is_ok()
    }
}

/// Signature from a committee node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// Hash of the public key that made the signature.
    pub public_key_id: H256,
    /// Ed25519 signature.
    pub signature: B512,
    /// Optional attestation verification report in case the contract is being executed
    /// in a TEE, attesting to the fact that a trusted hardware platform running specific
    /// code generated the signature.
    pub attestation: Option<Vec<u8>>,
}

impl Signature {
    /// Compute SHA-512/256 digest over (context, value).
    fn digest(context: &B64, value: &[u8]) -> H256 {
        let mut ctx = digest::Context::new(&digest::SHA512_256);
        ctx.update(context);
        ctx.update(value);
        H256::from(ctx.finish().as_ref())
    }

    /// Sign given value in given context using the given signer.
    pub fn sign(signer: &Signer, context: &B64, value: &[u8]) -> Self {
        let digest = Self::digest(context, value);

        Signature {
            public_key_id: signer.get_public_key_id(),
            signature: signer.sign(&digest),
            attestation: signer.attest(&digest),
        }
    }

    /// Verify signature and optional attestation.
    ///
    /// Note that you need to ensure that the attestation is actually present if
    /// attestation is required.
    pub fn verify(&self, verifier: &Verifier, context: &B64, value: &[u8]) -> bool {
        let digest = Self::digest(context, value);

        verifier.verify(&digest, &self.signature, self.attestation.as_ref())
    }
}

impl Encodable for Signature {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(3);
        stream.append(&self.public_key_id);
        stream.append(&self.signature);
        stream.append(&self.attestation);
    }
}

impl Decodable for Signature {
    fn decode(rlp: &UntrustedRlp) -> std::result::Result<Self, DecoderError> {
        Ok(Self {
            public_key_id: rlp.val_at(0)?,
            signature: rlp.val_at(1)?,
            attestation: rlp.val_at(2)?,
        })
    }
}

/// Signature from a committee node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed<T: Clone + Debug + PartialEq + Eq + Encodable + Decodable> {
    /// Signed value.
    value: T,
    /// Signature.
    pub signature: Signature,
}

impl<T: Clone + Debug + PartialEq + Eq + Encodable + Decodable> Signed<T> {
    /// Sign a new value.
    pub fn sign(signer: &Signer, context: &B64, value: T) -> Self {
        let signature = Signature::sign(signer, context, &rlp::encode(&value));

        Self { value, signature }
    }

    /// Verify signature and return signed value.
    pub fn open(self, verifier: &Verifier, context: &B64) -> Result<T> {
        // First verify signature.
        if !self.signature
            .verify(verifier, context, &rlp::encode(&self.value))
        {
            return Err(Error::new("signature verification failed"));
        }

        Ok(self.value)
    }
}

impl<T: Clone + Debug + PartialEq + Eq + Encodable + Decodable> Encodable for Signed<T> {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(2);
        stream.append(&self.value);
        stream.append(&self.signature);
    }
}

impl<T: Clone + Debug + PartialEq + Eq + Encodable + Decodable> Decodable for Signed<T> {
    fn decode(rlp: &UntrustedRlp) -> std::result::Result<Self, DecoderError> {
        Ok(Self {
            value: rlp.val_at(0)?,
            signature: rlp.val_at(1)?,
        })
    }
}
