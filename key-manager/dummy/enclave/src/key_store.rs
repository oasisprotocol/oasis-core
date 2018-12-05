use bincode;
use sodalite;
use std::str::FromStr;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutex as Mutex;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutexGuard as MutexGuard;
#[cfg(not(target_env = "sgx"))]
use std::sync::{Mutex, MutexGuard};

use ekiden_core::error::{Error, Result};
use ekiden_core::random;

use ekiden_keymanager_common::{ContractId, ContractKey, PublicKeyType, StateKeyType,
                               EMPTY_PRIVATE_KEY, EMPTY_PUBLIC_KEY, EMPTY_STATE_KEY};
use ekiden_trusted::db::{Database, DatabaseHandle};

/// Key store, which actually stores the key manager keys.
pub struct KeyStore;

lazy_static! {
    // Global key store object.
    static ref KEY_STORE: Mutex<KeyStore> = Mutex::new(KeyStore::new());
}

impl KeyStore {
    fn new() -> Self {
        let mut key_store = KeyStore;
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
    pub fn get_or_create_keys(&mut self, contract_id: ContractId) -> Result<ContractKey> {
        let mut key = Err(Error::new(format!(
            "Could not get or create keys for {:?}",
            contract_id
        )));

        DatabaseHandle::instance().with_encryption_key(self.encryption_key(), |db| {
            let serialized_key = db.get(&contract_id).unwrap_or_else(|| {
                let k = bincode::serialize(&Self::create_random_key()).unwrap();
                db.insert(&contract_id, &k);
                k
            });
            key = Ok(bincode::deserialize(&serialized_key).expect("Corrupted state"));
        });

        key
    }

    /// Get the public part of the key.
    pub fn get_public_key(&self, contract_id: ContractId) -> Result<PublicKeyType> {
        let mut public_key = Err(Error::new(format!(
            "The requested public key doesn't exist for {:?}",
            contract_id
        )));

        DatabaseHandle::instance().with_encryption_key(self.encryption_key(), |db| {
            let pk_serialized = db.get(&contract_id);
            if pk_serialized.is_none() {
                return;
            }
            let pk: ContractKey =
                bincode::deserialize(&pk_serialized.unwrap()).expect("Corrupted state");
            public_key = Ok(pk.input_keypair.get_pk());
        });

        public_key
    }

    /// Returns a random ContractKey.
    fn create_random_key() -> ContractKey {
        let mut seed = [0; 32];
        let mut public_key = EMPTY_PUBLIC_KEY;
        let mut private_key = EMPTY_PRIVATE_KEY;
        let mut state_key = EMPTY_STATE_KEY;

        random::get_random_bytes(&mut seed).expect("Should always get random bytes for the seed");
        sodalite::box_keypair_seed(&mut public_key, &mut private_key, &seed);
        random::get_random_bytes(&mut state_key)
            .expect("Should always get random bytes for a state key");

        ContractKey::new(public_key, private_key, state_key)
    }

    /// Dummy encryption key
    pub fn encryption_key(&self) -> StateKeyType {
        [
            255, 135, 103, 97, 49, 33, 200, 139, 130, 186, 54, 177, 83, 2, 162, 146, 160, 234, 231,
            218, 124, 160, 72, 113, 26, 177, 100, 40, 135, 129, 195, 50, 161, 220, 212, 120, 240,
            163, 240, 23, 9, 74, 150, 87, 253, 60, 105, 170, 133, 134, 109, 248, 100, 43, 4, 19,
            39, 25, 13, 138, 28, 49, 71, 49,
        ]
    }
}
