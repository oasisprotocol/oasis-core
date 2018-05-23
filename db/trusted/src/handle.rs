//! Low-level key-value database interface.
use std::sync::{Mutex, MutexGuard};
use std::sync::Arc;

#[cfg(target_env = "sgx")]
use serde_cbor;

use ekiden_common::bytes::H256;
use ekiden_common::error::Result;
#[cfg(target_env = "sgx")]
use ekiden_common::futures::FutureExt;
#[cfg(not(target_env = "sgx"))]
use ekiden_storage_dummy::DummyStorageBackend;

use super::Database;
use super::patricia_trie::PatriciaTrie;
#[cfg(target_env = "sgx")]
use super::untrusted::UntrustedStorageBackend;

/// Database handle.
///
/// This is a concrete implementation of the [`Database`] interface.
///
/// [`Database`]: super::Database
pub struct DatabaseHandle {
    /// Current database state.
    state: PatriciaTrie,
    /// Root hash.
    root_hash: Option<H256>,
}

lazy_static! {
    // Global database object.
    static ref DB: Mutex<DatabaseHandle> = Mutex::new(DatabaseHandle::new());
}

impl DatabaseHandle {
    /// Construct new database interface.
    fn new() -> Self {
        DatabaseHandle {
            #[cfg(not(target_env = "sgx"))]
            state: PatriciaTrie::new(Arc::new(DummyStorageBackend::new())),
            #[cfg(target_env = "sgx")]
            state: PatriciaTrie::new(Arc::new(UntrustedStorageBackend::new())),
            root_hash: None,
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
    pub(crate) fn set_root_hash(&mut self, root_hash: H256) -> Result<()> {
        if root_hash == H256::zero() {
            self.root_hash = None;
        } else {
            self.root_hash = Some(root_hash);
        }

        Ok(())
    }

    /// Return the root hash of the database state.
    pub(crate) fn get_root_hash(&mut self) -> Result<H256> {
        match self.root_hash {
            Some(root_hash) => Ok(root_hash),
            None => Ok(H256::zero()),
        }
    }
}

impl Database for DatabaseHandle {
    fn contains_key(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.state.get(self.root_hash, key)
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
        let previous_value = self.get(key);
        self.root_hash = Some(self.state.insert(self.root_hash, key, value));

        previous_value
    }

    fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let previous_value = self.get(key);
        self.root_hash = self.state.remove(self.root_hash, key);

        previous_value
    }

    /// Clear database state.
    fn clear(&mut self) {
        self.root_hash = None;
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

        assert!(db.contains_key(b"foo"));
        assert!(db.contains_key(b"bar"));
        assert_eq!(db.get(b"foo"), Some(b"hello world".to_vec()));
        assert_eq!(db.get(b"another"), None);

        db.remove(b"foo");

        assert!(!db.contains_key(b"foo"));
        assert!(db.contains_key(b"bar"));
        assert_eq!(db.get(b"foo"), None);

        db.clear();

        assert!(!db.contains_key(b"bar"));
    }
}
