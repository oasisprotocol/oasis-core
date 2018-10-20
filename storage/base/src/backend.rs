//! Storage backend interface.
use ekiden_common::bytes::H256;
use ekiden_common::futures::BoxFuture;
use ekiden_common::futures::BoxStream;
use ekiden_common::ring::digest;

use std::sync::Arc;

/// Insert options for the storage backend which can be passed as an
/// argument to the `insert` and `insert_batch` calls.
#[derive(Clone, Debug)]
pub struct InsertOptions {
    /// For storage backends which use a local layer and a remote/external
    /// layer, this flag signals that the given insert should only happen
    /// into the local layer.
    ///
    /// This is only safe if another node will perform a non-local commit.
    pub local_only: bool,
}

impl Default for InsertOptions {
    fn default() -> Self {
        InsertOptions { local_only: false }
    }
}

/// Storage backend implementing the Ekiden storage interface.
pub trait StorageBackend: Sync + Send {
    /// Fetch the value for a specific immutable key.
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>>;

    /// Fetch multiple values for specific immutable keys.
    fn get_batch(&self, keys: Vec<H256>) -> BoxFuture<Vec<Option<Vec<u8>>>>;

    /// Store a specific value into storage. It can be later retrieved by its hash.
    /// Expiry represents a number of Epochs for which the value should remain available.
    fn insert(&self, value: Vec<u8>, expiry: u64, opts: InsertOptions) -> BoxFuture<()>;

    /// Store multiple values into storage. They can be later retrieved by their
    /// hashes. The first element in the passed tuple is the value and the second
    /// element is the expiry time in the number of Epochs.
    ///
    /// If the storage backend is unable to store any of the values, no values will
    /// be stored.
    fn insert_batch(&self, values: Vec<(Vec<u8>, u64)>, opts: InsertOptions) -> BoxFuture<()>;

    // Get keys in the storage database, along with expirations.
    fn get_keys(&self) -> BoxStream<(H256, u64)>;
}

/// The hash algorithm used to generate a key from a value.
///
/// All backends should use this method to hash values.
pub fn hash_storage_key(value: &[u8]) -> H256 {
    H256::from(digest::digest(&digest::SHA512_256, &value).as_ref())
}
