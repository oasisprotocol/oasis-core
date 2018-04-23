//! Storage backend interface.
use ekiden_common::bytes::H256;
use ekiden_common::futures::BoxFuture;
use ekiden_common::ring::digest;

/// Storage backend implementing the Ekiden storage interface.
pub trait StorageBackend {
    /// Fetch the value for a specific immutable key.
    fn get(&self, key: &[u8]) -> BoxFuture<Vec<u8>>;

    /// Store a specific value into storage. It can be later retrieved by its hash.
    /// expiry
    fn insert(&self, value: &[u8], expiry: usize) -> BoxFuture<()>;

    // The hash algorithm used to generate a key from a value.
    fn to_key(value: &[u8]) -> Vec<u8> {
        let key = H256::from(digest::digest(&digest::SHA512_256, &value).as_ref());
        key.to_vec()
    }
}
