//! Low-level key-value database interface.
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::{Mutex, MutexGuard};

use ekiden_common::bytes::H256;
use ekiden_common::error::Result;
use ekiden_common::hash::empty_hash;
use ekiden_common::mrae::sivaessha2::{SivAesSha2, KEY_SIZE, NONCE_SIZE};
use ekiden_enclave_common::quote::MrEnclave;
use ekiden_keymanager_client::KeyManager;
#[cfg(not(target_env = "sgx"))]
use ekiden_keymanager_client::NetworkRpcClientBackendConfig;
use ekiden_keymanager_common::ContractId;
use ekiden_storage_base::mapper::BackendIdentityMapper;
#[cfg(not(target_env = "sgx"))]
use ekiden_storage_dummy::DummyStorageBackend;
use ekiden_storage_lru::LruCacheStorageBackend;

use super::patricia_trie::PatriciaTrie;
#[cfg(target_env = "sgx")]
use super::untrusted::UntrustedStorageBackend;
use super::Database;

/// Encryption context.
///
/// This contains the MRAE context for encrypting and decrypting values stored
/// in the database.
/// It is set up with db.with_encryption() and lasts only for the duration of
/// the closure that's passed to that method.
struct EncryptionContext {
    /// MRAE context.
    mrae_ctx: SivAesSha2,
    /// Nonce for the MRAE context (should be unique for all time for a given key).
    nonce: Vec<u8>,
}

/// Pending database operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Operation {
    /// Insert key with given value.
    Insert(Vec<u8>),
    /// Remove key.
    Remove,
}

/// Key manager configuration.
///
/// This is needed for connecting to the key manager when using the method
/// db.with_encryption().  Pass the struct with db.configure_key_manager().
pub struct DBKeyManagerConfig {
    /// Identity of key manager enclave.
    mrenclave: MrEnclave,
    /// gRPC config parameters (only if not running in an enclave).
    #[cfg(not(target_env = "sgx"))]
    grpc_config: NetworkRpcClientBackendConfig,
}

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
    /// Pending operations since the last root hash was set.
    pending_ops: HashMap<Vec<u8>, Operation>,
    /// Encryption context with which to perform all operations (optional).
    enc_ctx: Option<EncryptionContext>,
    /// Key manager config (optional).
    key_manager_config: Option<DBKeyManagerConfig>,
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
        let cached_backend = Arc::new(LruCacheStorageBackend::new(
            backend,
            Self::STORAGE_CACHE_SIZE,
        ));
        let mapper = Arc::new(BackendIdentityMapper::new(cached_backend));

        DatabaseHandle {
            state: PatriciaTrie::new(mapper),
            root_hash: None,
            pending_ops: HashMap::new(),
            enc_ctx: None,
            key_manager_config: None,
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

        self.pending_ops.clear();

        Ok(())
    }

    /// Return the root hash of the database state.
    pub fn get_root_hash(&mut self) -> Result<H256> {
        // Commit all pending writes to the trie.
        let mut root_hash = self.root_hash.clone();
        for (key, value) in self.pending_ops.drain() {
            match value {
                Operation::Insert(value) => {
                    root_hash = Some(self.state.insert(root_hash, &key, &value));
                }
                Operation::Remove => {
                    root_hash = self.state.remove(root_hash, &key);
                }
            }
        }

        self.root_hash = root_hash;
        match root_hash {
            Some(root_hash) => Ok(root_hash),
            None => Ok(empty_hash()),
        }
    }

    /// Set up key manager configuration.
    pub fn configure_key_manager(&mut self, config: DBKeyManagerConfig) {
        self.key_manager_config.get_or_insert(config);
    }
}

impl Database for DatabaseHandle {
    fn contains_key(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        // Fetch the current value by first checking the list of pending operations if they
        // affect the given key.
        let value = match self.pending_ops.get(key) {
            Some(Operation::Insert(value)) => Some(value.clone()),
            Some(Operation::Remove) => None,
            None => self.state.get(self.root_hash, key),
        };

        if self.enc_ctx.is_some() && value.is_some() {
            // Decrypt value using the encryption context.
            let ctx = self.enc_ctx.as_ref().unwrap();

            let decrypted = ctx.mrae_ctx.open(ctx.nonce.clone(), value.unwrap(), vec![]);

            decrypted.ok()
        } else {
            value
        }
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
        let previous_value = self.get(key);

        let value = match self.enc_ctx {
            Some(ref ctx) => {
                // Encrypt value using the encryption context.
                ctx.mrae_ctx
                    .seal(ctx.nonce.clone(), value.to_vec(), vec![])
                    .unwrap()
            }
            None => value.to_vec(),
        };

        // Add a pending insert operation for the given key.
        self.pending_ops
            .insert(key.to_vec(), Operation::Insert(value));

        previous_value
    }

    fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let previous_value = self.get(key);

        // Add a pending remove operation for the given key.
        self.pending_ops.insert(key.to_vec(), Operation::Remove);

        previous_value
    }

    fn rollback(&mut self) {
        self.pending_ops.clear();
    }

    fn with_encryption<F>(&mut self, contract_id: ContractId, f: F)
    where
        F: FnOnce(&mut DatabaseHandle) -> (),
    {
        // Make sure that the encryption context doesn't already exist,
        // as we don't support nested contexts.
        assert!(self.enc_ctx.is_none());

        // Make sure that the user has set a valid key manager configuration
        // with db.configure_key_manager() before calling us.
        assert!(self.key_manager_config.is_some());

        // Get encryption key from the key manager and set up encryption context.
        match KeyManager::get() {
            Ok(mut km) => {
                // First, configure the key manager client.
                let cfg = self.key_manager_config.as_ref().unwrap();

                #[cfg(not(target_env = "sgx"))]
                km.configure_backend(cfg.grpc_config.clone());

                km.set_contract(cfg.mrenclave);

                // Get state key from KM, then split it into two parts:
                // the MRAE key and the nonce.
                let (_pk, state_key) = km.get_or_create_secret_keys(contract_id).unwrap();
                let key: Vec<u8> = state_key.as_ref()[..KEY_SIZE].to_vec();
                let nonce: Vec<u8> = state_key.as_ref()[KEY_SIZE..KEY_SIZE + NONCE_SIZE].to_vec();

                // Set up encryption context.
                self.enc_ctx = Some(EncryptionContext {
                    mrae_ctx: SivAesSha2::new(key).unwrap(),
                    nonce,
                });
            }
            Err(e) => {
                panic!("Cannot get key manager instance: {}", e.description());
            }
        }

        // Run provided function.
        f(self);

        // Clear encryption context.
        // Keys are securely erased by the Drop handler on SivAesSha2,
        // we might want to do the same for the nonce.
        self.enc_ctx = None;
    }
}

#[cfg(test)]
mod tests {
    use ekiden_common::hash::empty_hash;
    use ekiden_keymanager_common::ContractId;

    use super::{Database, DatabaseHandle};

    use std::str::FromStr;

    #[test]
    fn test_basic_operations() {
        let mut db = DatabaseHandle::new();

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

        db.rollback();

        assert!(!db.contains_key(b"bar"));
        assert_eq!(db.get_root_hash(), Ok(empty_hash()));
    }

    #[test]
    fn test_get_after_flush() {
        let mut db = DatabaseHandle::new();

        db.insert(b"foo", b"hello world");

        assert_eq!(db.get(b"foo"), Some(b"hello world".to_vec()));
        assert_ne!(db.get_root_hash(), Ok(empty_hash()));
        assert_eq!(db.get(b"foo"), Some(b"hello world".to_vec()));
    }

    #[test]
    fn test_db_encryption() {
        let mut db = DatabaseHandle::new();

        db.insert(b"unencrypted", b"hello world");

        db.with_encryption(ContractId::from([0u8; 32]), |db| {
            db.insert(b"encrypted", b"top secret");
            assert!(db.contains_key(b"encrypted"));
        });

        // Encrypted value should actually be encrypted.
        assert_ne!(db.get(b"encrypted"), Some(b"top secret".to_vec()));

        // Unencrypted value should be readable.
        assert_eq!(db.get(b"unencrypted"), Some(b"hello world".to_vec()));

        // Accessing encrypted value with a different contract ID should fail.
        db.with_encryption(ContractId::from([42u8; 32]), |db| {
            assert_ne!(db.get(b"encrypted"), Some(b"top secret".to_vec()));
        });

        // Accessing encrypted value with the original contract ID should succeed.
        db.with_encryption(ContractId::from([0u8; 32]), |db| {
            assert_eq!(db.get(b"encrypted"), Some(b"top secret".to_vec()));
        });

        db.rollback();
        assert!(!db.contains_key(b"unencrypted"));
        assert!(!db.contains_key(b"encrypted"));
    }

    #[test]
    #[should_panic]
    fn test_db_encryption_nested() {
        let mut db = DatabaseHandle::new();

        let id_0 = ContractId::from_str(&"0".repeat(64)).unwrap();
        let id_1 = ContractId::from_str(&"1".repeat(64)).unwrap();

        // Nesting encryption contexts isn't supported and should panic!
        db.with_encryption(id_0, |db| {
            db.insert(b"encrypted", b"top secret");

            db.with_encryption(id_1, |db| {
                db.insert(b"also_encrypted", b"bottom secret");
            });
        });
    }
}
