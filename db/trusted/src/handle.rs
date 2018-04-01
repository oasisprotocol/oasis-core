//! Low-level key-value database interface.
use std::collections::HashMap;
#[cfg(not(target_env = "sgx"))]
use std::sync::{Mutex, MutexGuard};
#[cfg(target_env = "sgx")]
use std::sync::SgxMutex as Mutex;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutexGuard as MutexGuard;

use protobuf::{self, Message};

use ekiden_common::error::Result;

use super::Database;
use super::crypto;
use super::generated::database::{CryptoSecretbox, State, State_KeyValue};

/// Database handle.
///
/// This is a concrete implementation of the [`Database`] interface.
///
/// [`Database`]: super::Database
pub struct DatabaseHandle {
    /// Current database state.
    state: HashMap<Vec<u8>, Vec<u8>>,
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
        DatabaseHandle {
            state: HashMap::new(),
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

    /// Import database.
    pub(crate) fn import(&mut self, state: &CryptoSecretbox) -> Result<()> {
        let mut state: State = protobuf::parse_from_bytes(&crypto::decrypt_state(&state)?)?;

        self.state.clear();
        for kv in state.take_state().iter_mut() {
            self.state.insert(kv.take_key(), kv.take_value());
        }

        self.dirty = false;

        Ok(())
    }

    /// Export database.
    ///
    /// If nothing was modified since the last import, this method will return an
    /// uninitialized CryptoSecretbox.
    pub(crate) fn export(&mut self) -> Result<CryptoSecretbox> {
        if !self.dirty {
            // Database has not changed, we don't need to export anything.
            return Ok(CryptoSecretbox::new());
        }

        let mut state = State::new();
        {
            let items = state.mut_state();
            for (key, value) in &self.state {
                let mut item = State_KeyValue::new();
                item.set_key(key.clone());
                item.set_value(value.clone());

                items.push(item);
            }
        }

        Ok(crypto::encrypt_state(state.write_to_bytes()?)?)
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
