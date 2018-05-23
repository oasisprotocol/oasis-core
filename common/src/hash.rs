//! Structure hashing helpers.
use serde::Serialize;
use serde_cbor;

use super::bytes::H256;
use super::ring::digest;

/// Compute hashes of CBOR-encoded types.
pub trait EncodedHash {
    /// Return the hash of the current encoded type.
    fn get_encoded_hash(&self) -> H256;
}

impl<T: Serialize> EncodedHash for T {
    fn get_encoded_hash(&self) -> H256 {
        H256::from(digest::digest(&digest::SHA512_256, &serde_cbor::to_vec(self).unwrap()).as_ref())
    }
}

/// Hash of an empty string.
pub fn empty_hash() -> H256 {
    // This is SHA-512/256 of an empty string.
    H256::from("0xc672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a")
}
