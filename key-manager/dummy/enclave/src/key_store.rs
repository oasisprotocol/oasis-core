use bincode;
use sodalite;
use std::str::FromStr;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutex as Mutex;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutexGuard as MutexGuard;
#[cfg(not(target_env = "sgx"))]
use std::sync::{Mutex, MutexGuard};

use ekiden_core::{error::Result, random};

use ekiden_keymanager_common::{
    ContractId, ContractKey, PublicKeyType, StateKeyType, EMPTY_PRIVATE_KEY, EMPTY_PUBLIC_KEY,
    EMPTY_STATE_KEY,
};
use ekiden_trusted::db::{Database, DatabaseHandle};

/// A dummy key for use in tests where confidentiality is not needed.
const UNSECRET_ENCRYPTION_KEY: StateKeyType = [
    119, 206, 190, 82, 117, 21, 62, 84, 119, 212, 117, 60, 32, 158, 183, 32, 68, 55, 131, 112, 38,
    169, 217, 219, 58, 109, 194, 211, 89, 39, 198, 204, 254, 104, 202, 114, 203, 213, 89, 44, 192,
    168, 42, 136, 220, 230, 66, 74, 197, 220, 22, 146, 84, 121, 175, 216, 144, 182, 40, 179, 6, 73,
    177, 9,
];

/// Key store, which actually stores the key manager keys.
pub struct KeyStore {
    /// Dummy encryption key
    encryption_key: StateKeyType,
}

lazy_static! {
    // Global key store object.
    static ref KEY_STORE: Mutex<KeyStore> = Mutex::new(KeyStore::new());
}

impl KeyStore {
    fn new() -> Self {
        let mut key_store = KeyStore {
            encryption_key: UNSECRET_ENCRYPTION_KEY,
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
    pub fn get_or_create_keys(&mut self, contract_id: ContractId) -> Result<ContractKey> {
        DatabaseHandle::instance().with_encryption_key(self.encryption_key(), |db| {
            let serialized_key = db.get(&contract_id).unwrap_or_else(|| {
                let k = bincode::serialize(&Self::create_random_key()).unwrap();
                db.insert(&contract_id, &k);
                k
            });
            Ok(bincode::deserialize(&serialized_key).expect("Corrupted state"))
        })
    }

    /// Get the public part of the key.
    pub fn get_public_key(&self, contract_id: ContractId) -> Result<Option<PublicKeyType>> {
        DatabaseHandle::instance().with_encryption_key(self.encryption_key(), |db| {
            let pk_serialized = db.get(&contract_id);
            let result = pk_serialized
                .map(|pk| bincode::deserialize(&pk).expect("Corrupted state"))
                .and_then(|ck: ContractKey| Some(ck.input_keypair.get_pk()));
            Ok(result)
        })
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
        self.encryption_key
    }

    pub fn set_encryption_key(&mut self, encryption_key: StateKeyType) {
        self.encryption_key = encryption_key;
    }
}
