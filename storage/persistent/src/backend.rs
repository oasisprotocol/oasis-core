//! Ekiden storage interface.
extern crate ekiden_di;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_cbor;
use sled::{ConfigBuilder, Tree};

use ekiden_common::bytes::H256;
use ekiden_common::epochtime::local::SystemTimeSource;
use ekiden_common::epochtime::TimeSource;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::{future, BoxFuture};
use ekiden_storage_base::{hash_storage_key, StorageBackend};

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
    pub fn new(time: Box<TimeSource>, storage_base: &str) -> Result<Self> {
        let pb = PathBuf::from(&storage_base);
        if !pb.as_path().exists() {
            fs::create_dir(pb.as_path())?;
        }
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

// Register for dependency injection.
create_component!(
    persistent,
    "storage-backend",
    PersistentStorageBackend,
    StorageBackend,
    (|container: &mut Container| -> Result<Box<Any>> {
        let backend = match PersistentStorageBackend::new(Box::new(SystemTimeSource {}), "./") {
            Ok(backend) => backend,
            Err(e) => return Err(e.message.into()),
        };
        let instance: Arc<StorageBackend> = Arc::new(backend);
        Ok(Box::new(instance))
    }),
    []
);
