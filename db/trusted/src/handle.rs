//! Low-level key-value database interface.
use std::sync::Arc;
use std::sync::{Mutex, MutexGuard};

use ekiden_common::bytes::H256;
use ekiden_common::error::Result;
use ekiden_common::hash::empty_hash;
use ekiden_common::mrae::sivaessha2::{SivAesSha2, KEY_SIZE, NONCE_SIZE};
use ekiden_common::ring::digest;
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
    /// Encryption context with which to perform all operations (optional).
    enc_ctx: Option<EncryptionContext>,
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
            enc_ctx: None,
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
        let value = self.state.get(self.root_hash, key);

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

        if self.enc_ctx.is_some() {
            // Encrypt value using the encryption context.
            let ctx = self.enc_ctx.as_ref().unwrap();
            let encrypted_value = &ctx.mrae_ctx
                .seal(ctx.nonce.clone(), value.to_vec(), vec![])
                .unwrap();

            self.root_hash = Some(self.state.insert(self.root_hash, key, encrypted_value));
        } else {
            self.root_hash = Some(self.state.insert(self.root_hash, key, value));
        }

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

    /// Run given closure in an encrypted context for given contract.
    fn with_encryption<F>(&mut self, contract_id: ContractId, f: F)
    where
        F: FnOnce(&mut DatabaseHandle) -> (),
    {
        // TODO: Get encryption key from the key manager.

        // Set up dummy encryption key for now!
        let hash = digest::digest(&digest::SHA512, &contract_id.to_vec());
        let key: Vec<u8> = hash.as_ref()[..KEY_SIZE].to_vec();
        let nonce: Vec<u8> = hash.as_ref()[KEY_SIZE..KEY_SIZE + NONCE_SIZE].to_vec();

        // Make sure that the encryption context doesn't already exist,
        // as we don't support nested contexts.
        assert!(self.enc_ctx.is_none());

        // Set up encryption context.
        self.enc_ctx = Some(EncryptionContext {
            mrae_ctx: SivAesSha2::new(key).unwrap(),
            nonce,
        });

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

    #[test]
    fn test_db_encryption() {
        let mut db = DatabaseHandle::instance();

        db.clear();
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

        db.clear();
        assert!(!db.contains_key(b"unencrypted"));
        assert!(!db.contains_key(b"encrypted"));
    }

    #[test]
    #[should_panic]
    fn test_db_encryption_nested() {
        let mut db = DatabaseHandle::instance();

        db.clear();

        // Nesting encryption contexts isn't supported and should panic!
        db.with_encryption(ContractId::from([0u8; 32]), |db| {
            db.insert(b"encrypted", b"top secret");

            db.with_encryption(ContractId::from([42u8; 32]), |db| {
                db.insert(b"also_encrypted", b"bottom secret");
            });
        });
    }
}
