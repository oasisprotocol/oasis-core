//! Structure hashing helpers.
use super::bytes::H256;
use super::ring::digest;
use super::rlp::{self, Encodable};

/// Compute hashes of encoded types.
pub trait EncodedHash {
    /// Return the hash of the current encoded type.
    fn get_encoded_hash(&self) -> H256;
}

/// Compute hashes of encoded types.
pub trait EncodedListHash {
    /// Return the hash of the current encoded type.
    fn get_encoded_hash(&self) -> H256;
}

impl<T: Encodable> EncodedHash for T {
    fn get_encoded_hash(&self) -> H256 {
        H256::from(digest::digest(&digest::SHA512_256, &rlp::encode(self)).as_ref())
    }
}

impl<T: Encodable> EncodedListHash for Vec<T> {
    fn get_encoded_hash(&self) -> H256 {
        H256::from(digest::digest(&digest::SHA512_256, &rlp::encode_list(self)).as_ref())
    }
}
