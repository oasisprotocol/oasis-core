//! Storage mapper interface.
use ekiden_common::bytes::H256;
use ekiden_common::error::Result;
use ekiden_common::futures::{future, BoxFuture, Future};

use super::backend::{hash_storage_key, StorageBackend};

/// Storage mapper trait.
///
/// This trait can be used to apply transformations to values before they are sent to
/// the storage backend and after they are received. It can be used to implement things
/// like transparent authenticated encryption of values.
///
/// Every storage backend has an automatic trivial implementation of this trait which
/// enables easy composition of storage mappers.
pub trait StorageMapper: Sync + Send {
    /// Storage backend used by the mapper.
    fn backend(&self) -> &StorageBackend;

    /// Returns a get value mapper closure.
    ///
    /// The returned closure is used to transform values after they are received from
    /// the storage backend.
    fn map_get(&self) -> Box<Fn(Vec<u8>) -> Result<Vec<u8>> + Send + Sync> {
        // Default mapper is an identity.
        Box::new(|value| Ok(value))
    }

    /// Returns an insert value mapper closure.
    ///
    /// The returned closure is used to transform values before they are sent to the
    /// storage backend.
    fn map_insert(&self) -> Box<Fn(Vec<u8>) -> Result<Vec<u8>> + Send + Sync> {
        // Default mapper is an identity.
        Box::new(|value| Ok(value))
    }

    /// Fetch the value for a specific immutable key.
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let mapper = self.map_get();

        Box::new(self.backend().get(key).and_then(move |value| mapper(value)))
    }

    /// Store a specific value into storage. It can be later retrieved by its hash.
    /// Expiry represents a number of Epochs for which the value should remain available.
    ///
    /// Since the mapper can change the value before it is sent to the storage backend,
    /// this method also returns the hash of the transformed value.
    fn insert(&self, value: Vec<u8>, expiry: u64) -> BoxFuture<H256> {
        let value = match self.map_insert()(value) {
            Ok(value) => value,
            Err(error) => return Box::new(future::err(error)),
        };
        let key = hash_storage_key(&value);

        Box::new(
            self.backend()
                .insert(value, expiry)
                .and_then(move |_| Ok(key)),
        )
    }
}

// Each storage backend trivially implements the storage mapper interface.
impl<T: StorageBackend> StorageMapper for T {
    fn backend(&self) -> &StorageBackend {
        self
    }
}
