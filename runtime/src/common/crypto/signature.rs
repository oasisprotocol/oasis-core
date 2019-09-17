//! Signature types.
use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt};
use ed25519_dalek;
use failure::Fallible;
use rand::rngs::OsRng;
use serde_derive::{Deserialize, Serialize};

use super::hash::Hash;

impl_bytes!(
    PublicKey,
    ed25519_dalek::PUBLIC_KEY_LENGTH,
    "An Ed25519 public key."
);

/// Signature error.
#[derive(Debug, Fail)]
enum SignatureError {
    #[fail(display = "signature malleability check failed")]
    MalleabilityError,
}

static CURVE_ORDER: &'static [u64] = &[
    0x1000000000000000,
    0,
    0x14def9dea2f79cd6,
    0x5812631a5cf5d3ed,
];

/// An Ed25519 private key.
pub struct PrivateKey(pub ed25519_dalek::Keypair);

impl PrivateKey {
    /// Generates a new private key pair.
    pub fn generate() -> Self {
        let mut rng = OsRng::new().unwrap();

        PrivateKey(ed25519_dalek::Keypair::generate(&mut rng))
    }

    /// Generate a new private key from a test key seed.
    pub fn from_test_seed(seed: String) -> Self {
        let seed = Hash::digest_bytes(seed.as_bytes());
        let secret = ed25519_dalek::SecretKey::from_bytes(seed.as_ref()).unwrap();
        let pk: ed25519_dalek::PublicKey = (&secret).into();

        PrivateKey(ed25519_dalek::Keypair { secret, public: pk })
    }

    /// Returns the public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public.to_bytes())
    }
}

impl Signer for PrivateKey {
    fn sign(&self, context: &[u8], message: &[u8]) -> Fallible<Signature> {
        // TODO/#2103: Replace this with Ed25519ctx.
        let digest = Hash::digest_bytes_list(&[context, message]);

        Ok(Signature(self.0.sign(digest.as_ref()).to_bytes()))
    }
}

impl_bytes!(Signature, 64, "An Ed25519 signature.");

impl Signature {
    /// Verify signature.
    pub fn verify(&self, pk: &PublicKey, context: &[u8], message: &[u8]) -> Fallible<()> {
        // TODO/#2103: Replace this with Ed25519ctx.
        let pk = ed25519_dalek::PublicKey::from_bytes(pk.as_ref()).unwrap();
        let digest = Hash::digest_bytes_list(&[context, message]);
        let sig_slice = self.as_ref();
        let sig = ed25519_dalek::Signature::from_bytes(sig_slice).unwrap();

        // ed25519-dalek does not enforce the RFC 8032 mandated constraint
        // that s is in range [0, order), so signatures are malleable.
        if !sc_minimal(&sig_slice[32..]) {
            return Err(SignatureError::MalleabilityError.into());
        }

        Ok(pk.verify(digest.as_ref(), &sig)?)
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

// Check if s < L, per RFC 8032, inspired by the Go runtime library's version
// of this check.
fn sc_minimal(raw_s: &[u8]) -> bool {
    let mut rd = Cursor::new(raw_s);
    let mut s = [0u64; 4];

    // Read the raw scalar into limbs, and reverse it, because the raw
    // representation is little-endian.
    rd.read_u64_into::<LittleEndian>(&mut s[..]).unwrap();
    s.reverse();

    // Compare each limb, from most significant to least.
    for i in 0..4 {
        if s[i] > CURVE_ORDER[i] {
            return false;
        } else if s[i] < CURVE_ORDER[i] {
            return true;
        }
    }

    // The scalar is equal to the order of the curve.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sc_minimal() {
        // L - 2^0
        assert!(sc_minimal(&[
            0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10
        ]));

        // L - 2^64
        assert!(sc_minimal(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd5, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10
        ]));

        // L - 2^192
        assert!(sc_minimal(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd5, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x0f,
        ]));

        // L
        assert!(!sc_minimal(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10
        ]));

        // L + 2^0
        assert!(!sc_minimal(&[
            0xef, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10
        ]));

        // L + 2^64
        assert!(!sc_minimal(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd7, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10
        ]));

        // L + 2^128
        assert!(!sc_minimal(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10
        ]));

        // L + 2^192
        assert!(!sc_minimal(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10
        ]));

        // Scalar from the go runtime's test case.
        assert!(!sc_minimal(&[
            0x67, 0x65, 0x4b, 0xce, 0x38, 0x32, 0xc2, 0xd7, 0x6f, 0x8f, 0x6f, 0x5d, 0xaf, 0xc0,
            0x8d, 0x93, 0x39, 0xd4, 0xee, 0xf6, 0x76, 0x57, 0x33, 0x36, 0xa5, 0xc5, 0x1e, 0xb6,
            0xf9, 0x46, 0xb3, 0x1d,
        ]))
    }
}
