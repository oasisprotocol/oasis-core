//! Storage backend interface.
use ekiden_common::futures::BoxFuture;

/// Storage backend implementing the Ekiden storage interface.
pub trait StorageBackend {
    /// Fetch the value under a specific namespaced key.
    fn get(&self, namespace: &[u8], key: &[u8]) -> BoxFuture<Vec<u8>>;

    /// Update the value under a specific namespaced key.
    fn insert(&self, namespace: &[u8], key: &[u8], value: &[u8]) -> BoxFuture<()>;

    /// Remove the value under a specific namespaced key
    fn remove(&self, namespace: &[u8], key: &[u8]) -> BoxFuture<()>;
}
