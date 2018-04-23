//! Storage backend interface.
use ekiden_common::futures::BoxFuture;

/// Storage backend implementing the Ekiden storage interface.
pub trait StorageBackend {
    /// Fetch the value for a specific immutable key.
    fn get(&self, key: &[u8]) -> BoxFuture<Vec<u8>>;

    /// Store a specific value into storage. It can be later retrieved by its hash.
    fn insert(&self, value: &[u8]) -> BoxFuture<()>;
}
