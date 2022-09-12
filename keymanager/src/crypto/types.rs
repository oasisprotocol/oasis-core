use rand::{rngs::OsRng, Rng};
use x25519_dalek;
use zeroize::Zeroize;

use oasis_core_runtime::{common::crypto::signature::Signature, impl_bytes};

impl_bytes!(KeyPairId, 32, "A 256-bit key pair identifier.");
impl_bytes!(PublicKey, 32, "A public key.");

/// A private key.
#[derive(Clone, Default, cbor::Encode, cbor::Decode, Zeroize)]
#[cbor(transparent)]
#[zeroize(drop)]
pub struct PrivateKey(pub [u8; 32]);

/// A state encryption key.
#[derive(Clone, Default, cbor::Encode, cbor::Decode, Zeroize)]
#[cbor(transparent)]
#[zeroize(drop)]
pub struct StateKey(pub [u8; 32]);

impl AsRef<[u8]> for StateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A 256-bit master secret.
#[derive(Clone, Default, cbor::Encode, cbor::Decode, Zeroize)]
#[cbor(transparent)]
#[zeroize(drop)]
pub struct MasterSecret(pub [u8; 32]);

impl AsRef<[u8]> for MasterSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A key pair managed by the key manager.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct KeyPair {
    /// Input key pair (pk, sk)
    pub input_keypair: InputKeyPair,
    /// State encryption key
    pub state_key: StateKey,
    /// Checksum of the key manager state.
    pub checksum: Vec<u8>,
}

impl KeyPair {
    /// Generate a new random key (for testing).
    pub fn generate_mock() -> Self {
        let mut rng = OsRng {};
        let sk = x25519_dalek::StaticSecret::new(&mut rng);
        let pk = x25519_dalek::PublicKey::from(&sk);

        let mut state_key = StateKey::default();
        rng.fill(&mut state_key.0);

        KeyPair::new(
            PublicKey(*pk.as_bytes()),
            PrivateKey(sk.to_bytes()),
            state_key,
            vec![],
        )
    }

    /// Create a `KeyPair`.
    pub fn new(pk: PublicKey, sk: PrivateKey, k: StateKey, sum: Vec<u8>) -> Self {
        Self {
            input_keypair: InputKeyPair { pk, sk },
            state_key: k,
            checksum: sum,
        }
    }

    /// Create a `KeyPair` with only the public key.
    pub fn from_public_key(k: PublicKey, sum: Vec<u8>) -> Self {
        Self {
            input_keypair: InputKeyPair {
                pk: k,
                sk: PrivateKey::default(),
            },
            state_key: StateKey::default(),
            checksum: sum,
        }
    }
}

#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct InputKeyPair {
    /// Public key.
    pub pk: PublicKey,
    /// Private key.
    pub sk: PrivateKey,
}

/// Signed public key.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct SignedPublicKey {
    /// Public key.
    pub key: PublicKey,
    /// Checksum of the key manager state.
    pub checksum: Vec<u8>,
    /// Sign(sk, (key || checksum)) from the key manager.
    pub signature: Signature,
}
