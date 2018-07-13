//! Ekiden dummy consensus backend persistent local state storage.
use std::path::Path;
use std::sync::Arc;

use exonum_rocksdb::{Options, DB};

use ekiden_common::error::{Error, Result};

struct Inner {
    /// RocksDB database for storing key-value pairs.
    db: DB,
}

pub struct StateStorage {
    inner: Arc<Inner>,
}

impl StateStorage {
    /// Create new or open existing local persistent consensus state storage at given path.
    pub fn new(path: &Path) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_use_fsync(true);

        Ok(Self {
            inner: Arc::new(Inner {
                db: DB::open(&opts, path)?,
            }),
        })
    }

    /// Retrieve a value (bytes) from persistent storage using the given string key.
    pub fn get(&self, key: &str) -> Result<Vec<u8>> {
        match self.inner.db.get(key.as_bytes()) {
            Ok(Some(v)) => Ok(v.to_vec()),
            Ok(None) => Err(Error::new("key not found in DB")),
            _ => Err(Error::new("internal DB error")),
        }
    }

    /// Insert or update value (bytes) in persistent storage using the given string key.
    pub fn insert(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.inner.db.put(key.as_bytes(), &value)?;
        Ok(())
    }

    /// Remove value that corresponds to the given string key from persistent storage.
    pub fn remove(&self, key: &str) -> Result<()> {
        self.inner.db.delete(key.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::env::temp_dir;
    use std::fs::remove_dir_all;

    use super::*;

    #[test]
    fn test_local_state_storage() {
        // We'll create our test DB at /tmp/test_local_state_storage_db.
        let tmp_db_path = &temp_dir().as_path().join("test_local_state_storage_db");

        // Clean any possible leftovers from previous tests.
        drop(remove_dir_all(tmp_db_path));

        let state_storage = StateStorage::new(Path::new(tmp_db_path));

        assert!(state_storage.is_ok());

        let state_storage = state_storage.unwrap();

        let test_key = "test_key";
        let test_value: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7];

        assert_eq!(state_storage.insert(test_key, test_value.clone()), Ok(()));

        assert_eq!(state_storage.get(test_key).unwrap(), test_value);

        assert!(state_storage.remove(test_key).is_ok());

        assert!(state_storage.get(test_key).is_err());
    }
}
