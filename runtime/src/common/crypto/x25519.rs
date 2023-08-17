//! CBOR serializable X25519 types.
use anyhow::Result;
use rand::rngs::OsRng;
use x25519_dalek;
use zeroize::Zeroize;

use super::hash::Hash;

/// The length of an X25519 private key, in bytes.
pub const PRIVATE_KEY_LENGTH: usize = 32;

/// The length of an X25519 public key, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// A CBOR serializable Diffie-Hellman X25519 private key.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct PrivateKey(pub x25519_dalek::StaticSecret);

impl PrivateKey {
    /// Generate a new private key.
    pub fn generate() -> Self {
        PrivateKey(x25519_dalek::StaticSecret::random_from_rng(OsRng))
    }

    /// Compute corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(&self.0))
    }

    /// Generate a new private key from a test key seed.
    pub fn from_test_seed(seed: String) -> Self {
        let seed = Hash::digest_bytes(seed.as_bytes());
        Self::from(seed.0)
    }
}

impl From<[u8; PRIVATE_KEY_LENGTH]> for PrivateKey {
    /// Load private key from a byte array.
    fn from(bytes: [u8; PRIVATE_KEY_LENGTH]) -> PrivateKey {
        // We must clamp to match previous x25519-dalek behavior and the test vectors.
        let bytes = curve25519_dalek::scalar::clamp_integer(bytes);

        PrivateKey(x25519_dalek::StaticSecret::from(bytes))
    }
}

impl Default for PrivateKey {
    fn default() -> Self {
        Self::from([0; PRIVATE_KEY_LENGTH])
    }
}

impl cbor::Encode for PrivateKey {
    fn into_cbor_value(self) -> cbor::Value {
        cbor::to_value(self.0.to_bytes())
    }
}

impl cbor::Decode for PrivateKey {
    fn try_default() -> Result<Self, cbor::DecodeError> {
        Ok(Default::default())
    }

    fn try_from_cbor_value(value: cbor::Value) -> Result<Self, cbor::DecodeError> {
        let mut bytes: [u8; PRIVATE_KEY_LENGTH] = cbor::Decode::try_from_cbor_value(value)?;
        let pk = PrivateKey(x25519_dalek::StaticSecret::from(bytes));
        bytes.zeroize();
        Ok(pk)
    }
}

/// A CBOR serializable Diffie-Hellman X25519 public key.
#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct PublicKey(pub x25519_dalek::PublicKey);

impl From<[u8; PUBLIC_KEY_LENGTH]> for PublicKey {
    /// Load public key from a byte array.
    fn from(bytes: [u8; PUBLIC_KEY_LENGTH]) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(bytes))
    }
}

impl From<&PrivateKey> for PublicKey {
    /// Given an X25519 private key, compute its corresponding public key.
    fn from(sk: &PrivateKey) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(&sk.0))
    }
}

impl Default for PublicKey {
    fn default() -> Self {
        Self::from([0; PUBLIC_KEY_LENGTH])
    }
}

impl cbor::Encode for PublicKey {
    fn into_cbor_value(self) -> cbor::Value {
        cbor::to_value(*self.0.as_bytes())
    }
}

impl cbor::Decode for PublicKey {
    fn try_default() -> Result<Self, cbor::DecodeError> {
        Ok(Default::default())
    }

    fn try_from_cbor_value(value: cbor::Value) -> Result<Self, cbor::DecodeError> {
        let bytes: [u8; PUBLIC_KEY_LENGTH] = cbor::Decode::try_from_cbor_value(value)?;
        let pk = PublicKey(x25519_dalek::PublicKey::from(bytes));
        Ok(pk)
    }
}

#[cfg(test)]
mod tests {
    use crate::common::crypto::x25519::{PrivateKey, PublicKey, PRIVATE_KEY_LENGTH};

    #[test]
    fn cbor_serialization() {
        let sk = PrivateKey::from([1; PRIVATE_KEY_LENGTH]);
        let pk = PublicKey::from(&sk);

        // Encode/decode private key.
        let enc = cbor::to_vec(sk.clone());
        let dec: PrivateKey = cbor::from_slice(&enc).expect("deserialization should succeed");
        assert_eq!(
            sk.0.to_bytes(),
            dec.0.to_bytes(),
            "serialization should round-trip"
        );

        // Encode/decode public key.
        let enc = cbor::to_vec(pk.clone());
        let dec: PublicKey = cbor::from_slice(&enc).expect("deserialization should succeed");
        assert_eq!(
            pk.0.to_bytes(),
            dec.0.to_bytes(),
            "serialization should round-trip"
        );
    }
}
