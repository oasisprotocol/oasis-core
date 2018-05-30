//! Low-level key-value database interface.
use std::sync::Arc;
use std::sync::{Mutex, MutexGuard};

use ekiden_common::bytes::H256;
use ekiden_common::error::Result;
use ekiden_common::hash::empty_hash;
#[cfg(not(target_env = "sgx"))]
use ekiden_storage_dummy::DummyStorageBackend;
use ekiden_storage_lru::LruCacheStorageBackend;

use super::patricia_trie::PatriciaTrie;
#[cfg(target_env = "sgx")]
use super::untrusted::UntrustedStorageBackend;
use super::Database;

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
    /// Size of the in-memory storage cache (number of entries).
    const STORAGE_CACHE_SIZE: usize = 1024;

    /// Construct new database interface.
    fn new() -> Self {
        #[cfg(not(target_env = "sgx"))]
        let backend = Arc::new(DummyStorageBackend::new());
        #[cfg(target_env = "sgx")]
        let backend = Arc::new(UntrustedStorageBackend::new());

        DatabaseHandle {
            state: PatriciaTrie::new(Arc::new(LruCacheStorageBackend::new(
                backend,
                Self::STORAGE_CACHE_SIZE,
            ))),
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
        if root_hash == empty_hash() {
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
            None => Ok(empty_hash()),
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
    use ekiden_common::hash::empty_hash;

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
        assert_eq!(db.get_root_hash(), Ok(empty_hash()));
    }
}
