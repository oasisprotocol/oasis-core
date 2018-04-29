//! Signature interface.
use serde::Serialize;
use serde_cbor;

use super::bytes::{B256, B512, B64, H256};
use super::error::{Error, Result};
use super::ring::{digest, signature};
use super::untrusted;

/// Signer interface.
pub trait Signer {
    /// Sign given 256-bit digest.
    fn sign(&self, data: &H256) -> B512;

    /// Get the signing public key.
    fn get_public_key(&self) -> B256;

    /// Attest to given 256-bit digest.
    fn attest(&self, data: &H256) -> Option<Vec<u8>>;
}

/// Verifier interface.
pub trait Verifier {
    /// Verify signature and optional attestation.
    fn verify(&self, data: &H256, signature: &B512, attestation: Option<&Vec<u8>>) -> bool;
}

/// Null signer/verifier which does no signing and says everything is verified.
///
/// **This should only be used in tests.**
pub struct NullSignerVerifier;

impl Signer for NullSignerVerifier {
    fn sign(&self, _data: &H256) -> B512 {
        B512::zero()
    }

    fn get_public_key(&self) -> B256 {
        B256::zero()
    }

    fn attest(&self, _data: &H256) -> Option<Vec<u8>> {
        None
    }
}

impl Verifier for NullSignerVerifier {
    fn verify(&self, _data: &H256, _signature: &B512, _attestation: Option<&Vec<u8>>) -> bool {
        true
    }
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

    fn get_public_key(&self) -> B256 {
        B256::from(self.key_pair.public_key_bytes())
    }

    fn attest(&self, _data: &H256) -> Option<Vec<u8>> {
        None
    }
}

/// Public key verifier.
pub struct PublicKeyVerifier<'a> {
    /// Public key.
    public_key: &'a B256,
}

impl<'a> PublicKeyVerifier<'a> {
    pub fn new(public_key: &'a B256) -> Self {
        Self { public_key }
    }
}

impl<'a> Verifier for PublicKeyVerifier<'a> {
    fn verify(&self, data: &H256, signature: &B512, attestation: Option<&Vec<u8>>) -> bool {
        // TODO: Verify attestation.
        match attestation {
            Some(_) => return false,
            None => {}
        }

        signature::verify(
            &signature::ED25519,
            untrusted::Input::from(self.public_key),
            untrusted::Input::from(&data),
            untrusted::Input::from(&signature),
        ).is_ok()
    }
}

/// Signature from a committee node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Public key that made the signature.
    pub public_key: B256,
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
            public_key: signer.get_public_key(),
            signature: signer.sign(&digest),
            attestation: signer.attest(&digest),
        }
    }

    /// Verify signature and optional attestation.
    ///
    /// Note that you need to ensure that the attestation is actually present if
    /// attestation is required.
    pub fn verify(&self, context: &B64, value: &[u8]) -> bool {
        let digest = Self::digest(context, value);
        let verifier = PublicKeyVerifier::new(&self.public_key);

        verifier.verify(&digest, &self.signature, self.attestation.as_ref())
    }
}

/// Signature from a committee node.
#[derive(Serialize, Deserialize)]
pub struct Signed<T> {
    /// Signed value.
    value: T,
    /// Signature.
    pub signature: Signature,
}

impl<T> Signed<T> {
    /// Sign a new value.
    pub fn sign(signer: &Signer, context: &B64, value: T) -> Self
    where
        T: Serialize,
    {
        let signature = Signature::sign(signer, context, &serde_cbor::to_vec(&value).unwrap());

        Self { value, signature }
    }

    /// Verify signature and return signed value.
    pub fn open(self, context: &B64) -> Result<T>
    where
        T: Serialize,
    {
        // First verify signature.
        if !self.signature
            .verify(context, &serde_cbor::to_vec(&self.value).unwrap())
        {
            return Err(Error::new("signature verification failed"));
        }

        Ok(self.value)
    }

    /// Return value without verifying signature.
    ///
    /// Only use this variant if you have verified the signature yourself.
    pub fn get_value_unsafe(&self) -> &T {
        &self.value
    }
}

impl<T: Clone> Clone for Signed<T> {
    fn clone(&self) -> Self {
        Signed {
            value: self.value.clone(),
            signature: self.signature.clone(),
        }
    }
}
