//! Signature types.
use std::{cmp::Ordering, io::Cursor};

use anyhow::Result;
use byteorder::{LittleEndian, ReadBytesExt};
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use ed25519_dalek::{self, Signer as _};
use rand::rngs::OsRng;
use sha2::{Digest as _, Sha512};
use thiserror::Error;
use zeroize::Zeroize;

use super::hash::Hash;

impl_bytes!(
    PublicKey,
    ed25519_dalek::PUBLIC_KEY_LENGTH,
    "An Ed25519 public key."
);

/// Signature error.
#[derive(Error, Debug)]
enum SignatureError {
    #[error("point decompression failed")]
    PointDecompression,
    #[error("small order A")]
    SmallOrderA,
    #[error("small order R")]
    SmallOrderR,
    #[error("signature malleability check failed")]
    Malleability,
    #[error("invalid signature")]
    InvalidSignature,
}

static CURVE_ORDER: &[u64] = &[
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
        let mut rng = OsRng {};

        PrivateKey(ed25519_dalek::Keypair::generate(&mut rng))
    }

    /// Convert this private key into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.0.secret.to_bytes();
        let bvec = bytes.to_vec();
        bytes.zeroize();
        bvec
    }

    /// Construct a private key from bytes returned by `to_bytes`.
    ///
    /// # Panics
    ///
    /// This method will panic in case the passed bytes do not have the correct length.
    pub fn from_bytes(mut bytes: Vec<u8>) -> PrivateKey {
        let secret = ed25519_dalek::SecretKey::from_bytes(&bytes).unwrap();
        bytes.zeroize();
        #[allow(clippy::needless_borrow)]
        let public = (&secret).into();

        PrivateKey(ed25519_dalek::Keypair { secret, public })
    }

    /// Generate a new private key from a test key seed.
    pub fn from_test_seed(seed: String) -> Self {
        let seed = Hash::digest_bytes(seed.as_bytes());
        let secret = ed25519_dalek::SecretKey::from_bytes(seed.as_ref()).unwrap();
        #[allow(clippy::needless_borrow)]
        let pk: ed25519_dalek::PublicKey = (&secret).into();

        PrivateKey(ed25519_dalek::Keypair { secret, public: pk })
    }

    /// Returns the public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public.to_bytes())
    }
}

impl Signer for PrivateKey {
    fn sign(&self, context: &[u8], message: &[u8]) -> Result<Signature> {
        // TODO/#2103: Replace this with Ed25519ctx.
        let digest = Hash::digest_bytes_list(&[context, message]);

        Ok(Signature(self.0.sign(digest.as_ref()).to_bytes()))
    }
}

impl_bytes!(Signature, 64, "An Ed25519 signature.");

impl Signature {
    /// Verify signature.
    pub fn verify(&self, pk: &PublicKey, context: &[u8], message: &[u8]) -> Result<()> {
        // Apply the Oasis core specific domain separation.
        //
        // Note: This should be Ed25519ctx based but "muh Ledger".
        let digest = Hash::digest_bytes_list(&[context, message]);

        self.verify_raw(pk, digest.as_ref())
    }

    /// Verify signature without applying domain separation.
    #[allow(non_snake_case)] // Variable names matching RFC 8032 is more readable.
    pub fn verify_raw(&self, pk: &PublicKey, msg: &[u8]) -> Result<()> {
        // We have a very specific idea of what a valid Ed25519 signature
        // is, that is different from what ed25519-dalek defines, so this
        // needs to be done by hand.

        // Decompress A (PublicKey)
        //
        // TODO/perf:
        //  * PublicKey could just be an EdwardsPoint.
        //  * Could cache the results of is_small_order() in PublicKey.
        let A = CompressedEdwardsY::from_slice(pk.as_ref());
        let A = match A.decompress() {
            Some(point) => point,
            None => return Err(SignatureError::PointDecompression.into()),
        };
        if A.is_small_order() {
            return Err(SignatureError::SmallOrderA.into());
        }

        // Decompress R (signature point), S (signature scalar).
        //
        // Note:
        //  * Reject S > L, small order A/R
        //  * Accept non-canonical A/R
        let sig_slice = self.as_ref();
        let R_bits = &sig_slice[..32];
        let S_bits = &sig_slice[32..];

        let R = CompressedEdwardsY::from_slice(R_bits);
        let R = match R.decompress() {
            Some(point) => point,
            None => return Err(SignatureError::PointDecompression.into()),
        };
        if R.is_small_order() {
            return Err(SignatureError::SmallOrderR.into());
        }

        if !sc_minimal(S_bits) {
            return Err(SignatureError::Malleability.into());
        }
        let mut S: [u8; 32] = [0u8; 32];
        S.copy_from_slice(S_bits);
        let S = Scalar::from_bits(S);

        // k = H(R,A,m)
        let mut k: Sha512 = Sha512::new();
        k.update(R_bits);
        k.update(pk.as_ref());
        k.update(&msg);
        let k = Scalar::from_hash(k);

        // Check the cofactored group equation ([8][S]B = [8]R + [8][k]A').
        let neg_A = -A;
        let should_be_small_order =
            EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &neg_A, &S) - R;
        match should_be_small_order.is_small_order() {
            true => Ok(()),
            false => Err(SignatureError::InvalidSignature.into()),
        }
    }
}

/// Blob signed with one public key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct Signed {
    /// Signed blob.
    #[cbor(rename = "untrusted_raw_value")]
    pub blob: Vec<u8>,
    /// Signature over the blob.
    pub signature: SignatureBundle,
}

/// Blob signed by multiple public keys.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct MultiSigned {
    /// Signed blob.
    #[cbor(rename = "untrusted_raw_value")]
    pub blob: Vec<u8>,
    /// Signatures over the blob.
    pub signatures: Vec<SignatureBundle>,
}

/// A signature bundled with a public key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct SignatureBundle {
    /// Public key that produced the signature.
    pub public_key: PublicKey,
    /// Actual signature.
    pub signature: Signature,
}

impl SignatureBundle {
    /// Verify returns true iff the signature is valid over the given context
    /// and message.
    pub fn verify(&self, context: &[u8], message: &[u8]) -> bool {
        self.signature
            .verify(&self.public_key, context, message)
            .is_ok()
    }
}

/// A abstract signer.
pub trait Signer: Send + Sync {
    /// Generates a signature over the context and message.
    fn sign(&self, context: &[u8], message: &[u8]) -> Result<Signature>;
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
        match s[i].cmp(&CURVE_ORDER[i]) {
            Ordering::Greater => return false,
            Ordering::Less => return true,
            Ordering::Equal => {}
        }
    }

    // The scalar is equal to the order of the curve.
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hex::FromHex;

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

    #[test]
    fn test_private_key_to_bytes() {
        let secret = PrivateKey::generate();
        let bytes = secret.to_bytes();
        let from_bytes = PrivateKey::from_bytes(bytes);
        assert_eq!(secret.public_key(), from_bytes.public_key());
    }

    #[test]
    #[should_panic]
    fn test_private_key_to_bytes_malformed_a() {
        PrivateKey::from_bytes(vec![]);
    }

    #[test]
    #[should_panic]
    fn test_private_key_to_bytes_malformed_b() {
        PrivateKey::from_bytes(vec![1, 2, 3]);
    }

    #[test]
    fn verification_small_order_a() {
        // Case 1 from ed25519-speccheck
        let pbk = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa";
        let msg = "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79";
        let sig = "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04";

        let pbk: Vec<u8> = pbk.from_hex().unwrap();
        let msg: Vec<u8> = msg.from_hex().unwrap();
        let sig: Vec<u8> = sig.from_hex().unwrap();

        let pbk = PublicKey::from(pbk);
        let sig = Signature::from(sig);

        assert!(
            sig.verify_raw(&pbk, &msg).is_err(),
            "small order A not rejected"
        )
    }

    #[test]
    fn verification_small_order_r() {
        // Case 2 from ed25519-speccheck
        let pbk = "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43";
        let msg = "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab";
        let sig = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e";

        let pbk: Vec<u8> = pbk.from_hex().unwrap();
        let msg: Vec<u8> = msg.from_hex().unwrap();
        let sig: Vec<u8> = sig.from_hex().unwrap();

        let pbk = PublicKey::from(pbk);
        let sig = Signature::from(sig);

        assert!(
            sig.verify_raw(&pbk, &msg).is_err(),
            "small order R not rejected"
        )
    }

    #[test]
    fn verification_is_cofactored() {
        // Case 4 from ed25519-speccheck
        let pbk = "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d";
        let msg = "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c";
        let sig = "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09";

        let pbk: Vec<u8> = pbk.from_hex().unwrap();
        let msg: Vec<u8> = msg.from_hex().unwrap();
        let sig: Vec<u8> = sig.from_hex().unwrap();

        let pbk = PublicKey::from(pbk);
        let sig = Signature::from(sig);

        assert!(
            sig.verify_raw(&pbk, &msg).is_ok(),
            "verification is not cofactored(?)"
        )
    }

    // Note: It is hard to test rejects small order A/R combined with
    // accepts non-canonical A/R as there are no known non-small order
    // points with a non-canonical encoding, that are not also small
    // order.
}
