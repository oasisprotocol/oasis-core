//! Signature types.
use failure::Fallible;
use ring::{
    rand,
    signature::{verify, Ed25519KeyPair, KeyPair, ED25519},
};
use serde_derive::{Deserialize, Serialize};
use untrusted;

use super::hash::Hash;

impl_bytes!(PublicKey, 32, "An Ed25519 public key.");

/// An Ed25519 private key.
pub struct PrivateKey(pub Ed25519KeyPair);

impl PrivateKey {
    /// Generates a new private key pair.
    pub fn generate() -> Self {
        let rng = rand::SystemRandom::new();
        let key_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .unwrap()
            .as_ref()
            .to_vec();
        let key = Ed25519KeyPair::from_pkcs8(untrusted::Input::from(&key_pkcs8)).unwrap();

        PrivateKey(key)
    }

    /// Generate a new private key from a test key seed.
    pub fn from_test_seed(seed: String) -> Self {
        let seed = Hash::digest_bytes(seed.as_bytes());
        let key =
            Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(seed.as_ref())).unwrap();

        PrivateKey(key)
    }

    /// Loads the private key pair from PKCS8 encoded data.
    pub fn from_pkcs8(key: &[u8]) -> Fallible<Self> {
        let key = Ed25519KeyPair::from_pkcs8(untrusted::Input::from(key))?;
        Ok(PrivateKey(key))
    }

    /// Returns the public key.
    pub fn public_key(&self) -> PublicKey {
        let mut data = [0u8; 32];
        data[..].copy_from_slice(self.0.public_key().as_ref());

        PublicKey(data)
    }
}

impl Signer for PrivateKey {
    fn sign(&self, context: &[u8], message: &[u8]) -> Fallible<Signature> {
        let digest = Hash::digest_bytes_list(&[context, message]);

        let mut result = [0u8; 64];
        result[..].copy_from_slice(self.0.sign(digest.as_ref()).as_ref());

        Ok(Signature(result))
    }
}

impl_bytes!(Signature, 64, "An Ed25519 signature.");

impl Signature {
    /// Verify signature.
    pub fn verify(&self, pk: &PublicKey, context: &[u8], message: &[u8]) -> Fallible<()> {
        let digest = Hash::digest_bytes_list(&[context, message]);

        let pk = untrusted::Input::from(pk.as_ref());
        let digest = untrusted::Input::from(digest.as_ref());
        let sig = untrusted::Input::from(self.as_ref());

        Ok(verify(&ED25519, pk, digest, sig)?)
    }
}

/// A signature bundled with a public key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignatureBundle {
    /// Public key that produced the signature.
    pub public_key: Option<PublicKey>,
    /// Actual signature.
    pub signature: Signature,
}

/// A abstract signer.
pub trait Signer: Send + Sync {
    /// Generates a signature over the context and message.
    fn sign(&self, context: &[u8], message: &[u8]) -> Fallible<Signature>;
}
