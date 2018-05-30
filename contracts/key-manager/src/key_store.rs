use std::collections::hash_map::Entry;
use std::collections::HashMap;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutex as Mutex;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutexGuard as MutexGuard;
#[cfg(not(target_env = "sgx"))]
use std::sync::{Mutex, MutexGuard};

use ekiden_core::enclave::quote::MrEnclave;
use ekiden_core::error::{Error, Result};
use ekiden_core::random;

/// Key store, which actually stores the key manager keys.
pub struct KeyStore {
    /// Key store map.
    keys: HashMap<MrEnclave, HashMap<String, Vec<u8>>>,
}

lazy_static! {
    // Global key store object.
    static ref KEY_STORE: Mutex<KeyStore> = Mutex::new(KeyStore::new());
}

impl KeyStore {
    const MAX_KEY_SIZE: usize = 128;

    fn new() -> Self {
        KeyStore {
            keys: HashMap::new(),
        }
    }

    /// Get global key store instance.
    ///
    /// Calling this method will take a lock on the global instance, which will
    /// be released once the value goes out of scope.
    pub fn get<'a>() -> MutexGuard<'a, KeyStore> {
        KEY_STORE.lock().unwrap()
    }

    /// Generate a new random key.
    pub fn generate_key(size: usize) -> Result<Vec<u8>> {
        if size > KeyStore::MAX_KEY_SIZE {
            return Err(Error::new("Key too large"));
        }

        let mut key = vec![0; size];
        random::get_random_bytes(&mut key)?;

        Ok(key)
    }

    /// Get or create a named key.
    ///
    /// Each contract (identified by its MRENCLAVE) can store multiple keys in the
    /// key store, each is identified by its name string. The key size must be
    /// specified and is checked when retrieving an existing key.
    pub fn get_or_create_key(
        &mut self,
        mr_enclave: &MrEnclave,
        name: &str,
        size: usize,
    ) -> Result<Vec<u8>> {
        let key = match self.keys.entry(mr_enclave.clone()) {
            Entry::Occupied(mut entry) => {
                // This enclave already has some keys stored. Check if it also stores
                // the target named key.
                match entry.get_mut().entry(name.to_string()) {
                    Entry::Occupied(entry) => entry.get().clone(),
                    Entry::Vacant(entry) => {
                        let key = KeyStore::generate_key(size)?;
                        entry.insert(key).clone()
                    }
                }
            }
            Entry::Vacant(mut entry) => {
                // This enclave has nothing stored yet. Create an empty hashmap for it
                // and create the given key.
                let key = KeyStore::generate_key(size)?;
                let new_key = key.clone();
                let mut map = HashMap::new();
                map.insert(name.to_string(), key);
                entry.insert(map);

                new_key
            }
        };

        // Check key length.
        if key.len() != size {
            return Err(Error::new("Existing key with incompatible length"));
        }

        Ok(key)
    }
}
