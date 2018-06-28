//! Ekiden storage interface.
use std::fs;
use std::path::Path;
use std::sync::Arc;

use sled::{ConfigBuilder, Tree};

use ekiden_common::bytes::H256;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::prelude::*;
use ekiden_storage_base::{hash_storage_key, StorageBackend};

struct Inner {
    /// The actual sled database.
    storage: Tree,
}

pub struct PersistentStorageBackend {
    inner: Arc<Inner>,
}

impl PersistentStorageBackend {
    pub fn new(path: &Path) -> Result<Self> {
        if !path.exists() {
            fs::create_dir(path)?;
        }
        let config = ConfigBuilder::default().path(path);

        Ok(Self {
            inner: Arc::new(Inner {
                storage: Tree::start(config.build())?,
            }),
        })
    }
}

/// StorageBackend defines the actual storage interface of getting and setting data.
impl StorageBackend for PersistentStorageBackend {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let inner = self.inner.clone();
        let key = key.to_owned();

        future::lazy(move || match inner.storage.get(&key.to_vec()) {
            Ok(Some(vec)) => Ok(vec),
            _ => Err(Error::new("no key found")),
        }).into_box()
    }

    fn insert(&self, value: Vec<u8>, _expiry: u64) -> BoxFuture<()> {
        let inner = self.inner.clone();
        let key = hash_storage_key(&value);

        future::lazy(move || {
            inner.storage.set(key.to_vec(), value)?;

            Ok(())
        }).into_box()
    }
}

// Register for dependency injection.
create_component!(
    persistent,
    "storage-backend",
    PersistentStorageBackend,
    StorageBackend,
    (|container: &mut Container| -> Result<Box<Any>> {
        let args = container.get_arguments().unwrap();
        let db_path = args.value_of("storage-path").unwrap();

        let backend = match PersistentStorageBackend::new(Path::new(db_path)) {
            Ok(backend) => backend,
            Err(error) => return Err(error.message.into()),
        };

        let instance: Arc<StorageBackend> = Arc::new(backend);
        Ok(Box::new(instance))
    }),
    [Arg::with_name("storage-path")
        .long("storage-path")
        .help("Path to storage directory")
        .default_value("persistent_storage")
        .takes_value(true)]
);
