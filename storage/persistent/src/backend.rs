//! Ekiden storage interface.
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64;
use serde_cbor;
use sled::{ConfigBuilder, Tree};

use ekiden_common::bytes::{B256, H256};
use ekiden_common::epochtime::TimeSource;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::{future, BoxFuture};
use ekiden_storage_base::{StorageBackend, hash_storage_key};

pub const PERSISTENT_STORAGE_BASE_PATH: &str = "storage_base";

struct PersistentStorageBackendInner {
    /// The actual sled database.
    storage: Tree,
    /// A time source for learning the current epoch.
    time_source: Box<TimeSource>,
}

pub struct PersistentStorageBackend {
    inner: Arc<Mutex<PersistentStorageBackendInner>>,
}

impl PersistentStorageBackend {
    pub fn new(
        contract_id: B256,
        time: Box<TimeSource>,
        config: HashMap<String, String>,
    ) -> Result<Self> {
        let db_path = base64::encode(&contract_id);
        let storage_base = match config.get(PERSISTENT_STORAGE_BASE_PATH) {
            Some(base) => base,
            None => "./",
        };
        let mut pb = PathBuf::from(&storage_base);
        if !pb.as_path().exists() {
            fs::create_dir(pb.as_path())?;
        }
        pb.push(db_path);
        let config = ConfigBuilder::default().path(pb.as_path());

        Ok(Self {
            inner: Arc::new(Mutex::new(PersistentStorageBackendInner {
                storage: Tree::start(config.build()).unwrap(),
                time_source: time,
            })),
        })
    }
}

/// StorageBackend defines the actual storage interface of getting and setting data.
impl StorageBackend for PersistentStorageBackend {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let inner = self.inner.clone();
        let key = key.to_owned();

        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            match inner.storage.get(&key.to_vec()) {
                Ok(Some(vec)) => Ok(vec),
                _ => Err(Error::new("no key found")),
            }
        }))
    }

    fn insert(&self, value: Vec<u8>, expiry: u64) -> BoxFuture<()> {
        let inner = self.inner.clone();
        let key = hash_storage_key(&value);

        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            let now = inner.time_source.get_epoch()?;
            let expiry_key = format!("expire_{}", now.0 + expiry).into_bytes();

            // Add this item into the expiry accounting.
            let expiry_value = match inner.storage.get(&expiry_key) {
                Ok(Some(val)) => {
                    let mut list: Vec<H256> = serde_cbor::from_slice(&val).unwrap();
                    list.append(&mut vec![key]);
                    serde_cbor::to_vec(&list)
                }
                _ => serde_cbor::to_vec(&vec![key.clone()]),
            };
            inner.storage.set(expiry_key, expiry_value.unwrap())?;

            inner.storage.set(key.to_vec(), value)?;

            Ok(())
        }))
    }
}
