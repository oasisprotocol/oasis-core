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
    fn insert(&self, value: &[u8], expiry: u64) -> BoxFuture<()>;

    // The hash algorithm used to generate a key from a value.
    fn hash_key(value: &[u8]) -> H256 {
        H256::from(digest::digest(&digest::SHA512_256, &value).as_ref())
    }
}
