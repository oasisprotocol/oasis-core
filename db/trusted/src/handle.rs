//! Low-level key-value database interface.
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};
use std::sync::Arc;

#[cfg(target_env = "sgx")]
use serde_cbor;

use ekiden_common::bytes::H256;
use ekiden_common::error::Result;
#[cfg(target_env = "sgx")]
use ekiden_common::futures::FutureExt;
#[cfg(target_env = "sgx")]
use ekiden_key_manager_client::KeyManager;
use ekiden_storage_base::StorageMapper;
#[cfg(not(target_env = "sgx"))]
use ekiden_storage_dummy::DummyStorageBackend;

use super::Database;
#[cfg(target_env = "sgx")]
use super::aead::AeadStorageMapper;
#[cfg(target_env = "sgx")]
use super::untrusted::UntrustedStorageBackend;

/// Database handle.
///
/// This is a concrete implementation of the [`Database`] interface.
///
/// [`Database`]: super::Database
pub struct DatabaseHandle {
    /// Storage backend.
    backend: Arc<StorageMapper>,
    /// Current database state.
    state: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Dirtyness flag.
    dirty: bool,
}

lazy_static! {
    // Global database object.
    static ref DB: Mutex<DatabaseHandle> = Mutex::new(DatabaseHandle::new());
}

impl DatabaseHandle {
    /// Construct new database interface.
    fn new() -> Self {
        #[cfg(target_env = "sgx")]
        let mut key_manager = KeyManager::get().unwrap();

        DatabaseHandle {
            #[cfg(target_env = "sgx")]
            backend: Arc::new(AeadStorageMapper::new(
                Arc::new(UntrustedStorageBackend::new()),
                key_manager
                    .get_or_create_key("state.key", AeadStorageMapper::key_len())
                    .unwrap(),
                key_manager.get_or_create_key("state.nonce", 64).unwrap(),
            )),
            #[cfg(not(target_env = "sgx"))]
            backend: Arc::new(DummyStorageBackend::new()),
            state: BTreeMap::new(),
            dirty: false,
        }
    }

    /// Get global database interface instance.
    ///
    /// Calling this method will take a lock on the global instance, which will
    /// be released once the value goes out of scope.
    pub fn instance<'a>() -> MutexGuard<'a, DatabaseHandle> {
        DB.lock().unwrap()
    }

    /// Set the root hash of the database state.
    #[cfg(target_env = "sgx")]
    pub(crate) fn set_root_hash(&mut self, root_hash: H256) -> Result<()> {
        // TODO: Do not store a single blob.
        if let Ok(state) = self.backend.get(root_hash).wait() {
            self.state = serde_cbor::from_slice(&state)?;
        }
        self.dirty = false;

        Ok(())
    }

    /// Set the root hash of the database state.
    #[cfg(not(target_env = "sgx"))]
    pub(crate) fn set_root_hash(&mut self, _root_hash: H256) -> Result<()> {
        self.state.clear();
        self.dirty = false;

        Ok(())
    }

    /// Return the root hash of the database state.
    #[cfg(target_env = "sgx")]
    pub(crate) fn get_root_hash(&mut self) -> Result<H256> {
        // TODO: Do not store a single blob.
        let state = serde_cbor::to_vec(&self.state)?;
        // TODO: Handle state expiry.
        Ok(self.backend.insert(state, 7).wait()?)
    }

    /// Return the root hash of the database state.
    #[cfg(not(target_env = "sgx"))]
    pub(crate) fn get_root_hash(&mut self) -> Result<H256> {
        Ok(H256::zero())
    }
}

impl Database for DatabaseHandle {
    fn contains_key(&self, key: &[u8]) -> bool {
        self.state.contains_key(key)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.state.get(key).cloned()
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
        self.dirty = true;
        self.state.insert(key.to_owned(), value.to_owned())
    }

    fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.dirty = true;
        self.state.remove(key)
    }

    /// Clear database state.
    fn clear(&mut self) {
        self.dirty = true;
        self.state.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{Database, DatabaseHandle};

    #[test]
    fn test_basic_operations() {
        let mut db = DatabaseHandle::instance();

        db.clear();
        db.insert(b"foo", b"hello world");
        db.insert(b"bar", b"another data value");

        assert_eq!(db.get(b"foo"), Some(b"hello world".to_vec()));
        assert_eq!(db.get(b"another"), None);

        db.remove(b"foo");

        assert_eq!(db.get(b"foo"), None);
    }
}
