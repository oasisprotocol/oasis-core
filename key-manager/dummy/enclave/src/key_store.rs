use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::str::FromStr;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutex as Mutex;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutexGuard as MutexGuard;
#[cfg(not(target_env = "sgx"))]
use std::sync::{Mutex, MutexGuard};

use ekiden_core::error::{Error, Result};
use ekiden_core::random;

use ekiden_keymanager_common::{ContractId, ContractKey, PublicKeyType, EMPTY_PRIVATE_KEY,
                               EMPTY_PUBLIC_KEY, EMPTY_STATE_KEY};
use sodalite;

/// Key store, which actually stores the key manager keys.
pub struct KeyStore {
    /// Key store map.
    keys: HashMap<ContractId, ContractKey>,
}

lazy_static! {
    // Global key store object.
    static ref KEY_STORE: Mutex<KeyStore> = Mutex::new(KeyStore::new());
}

impl KeyStore {
    fn new() -> Self {
        let mut key_store = KeyStore {
            keys: HashMap::new(),
        };

        // for testing purpose, insert a special key at address 0
        key_store
            .get_or_create_keys(ContractId::from_str(&"0".repeat(64)).unwrap())
            .unwrap();

        return key_store;
    }

    /// Get global key store instance.
    ///
    /// Calling this method will take a lock on the global instance, which will
    /// be released once the value goes out of scope.
    pub fn get<'a>() -> MutexGuard<'a, KeyStore> {
        KEY_STORE.lock().unwrap()
    }

    /// Get or create keys.
    pub fn get_or_create_keys(&mut self, name: ContractId) -> Result<ContractKey> {
        let key = match self.keys.entry(name) {
            Entry::Occupied(entry) => {
                // This enclave already has some keys stored. Check if it also stores
                // the target named key.
                entry.get().clone()
            }
            Entry::Vacant(mut entry) => {
                // This enclave has nothing stored yet. Create an empty hashmap for it
                // and create the given key.

                let mut seed = [0; 32];
                let mut public_key = EMPTY_PUBLIC_KEY;
                let mut private_key = EMPTY_PRIVATE_KEY;
                let mut state_key = EMPTY_STATE_KEY;

                random::get_random_bytes(&mut seed)?;
                sodalite::box_keypair_seed(&mut public_key, &mut private_key, &seed);

                random::get_random_bytes(&mut state_key)?;

                entry
                    .insert(ContractKey::new(public_key, private_key, state_key))
                    .clone()
            }
        };

        Ok(key)
    }

    /// Get the public part of the key.
    pub fn get_public_key(&self, contract_id: ContractId) -> Result<PublicKeyType> {
        match self.keys.get(&contract_id) {
            Some(key) => Ok(key.input_keypair.get_pk()),
            None => Err(Error::new("Requested public key doesn't exist")),
        }
    }
}
