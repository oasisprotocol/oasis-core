//! Storage backend interface.
use ekiden_common::futures::BoxFuture;

/// Storage backend implementing the Ekiden storage interface.
pub trait StorageBackend {
    /// Fetch the value under a specific namespaced key.
    fn get(&self, key: &[u8]) -> BoxFuture<Vec<u8>>;

    /// Update the value under a specific namespaced key.
    fn insert(&self, value: &[u8]) -> BoxFuture<()>;
}
