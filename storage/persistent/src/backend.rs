//! Ekiden storage interface.
use std::path::Path;
use std::sync::Arc;

use exonum_rocksdb::{IteratorMode, WriteBatch, DB};

use ekiden_common::bytes::H256;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::prelude::*;
use ekiden_storage_base::{hash_storage_key, StorageBackend};

struct Inner {
    /// RocksDB database.
    db: DB,
}

pub struct PersistentStorageBackend {
    inner: Arc<Inner>,
}

impl PersistentStorageBackend {
    pub fn new(path: &Path) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(Inner {
                db: DB::open_default(path)?,
            }),
        })
    }
}

/// StorageBackend defines the actual storage interface of getting and setting data.
impl StorageBackend for PersistentStorageBackend {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let inner = self.inner.clone();
        let key = key.to_owned();

        future::lazy(move || match inner.db.get(&key) {
            Ok(Some(vec)) => Ok(vec.to_vec()),
            _ => Err(Error::new("no key found")),
        }).into_box()
    }

    fn get_batch(&self, keys: Vec<H256>) -> BoxFuture<Vec<Option<Vec<u8>>>> {
        let inner = self.inner.clone();

        future::lazy(move || {
            let mut results = vec![];

            for key in keys {
                results.push(match inner.db.get(&key)? {
                    Some(value) => Some(value.to_vec()),
                    None => None,
                });
            }

            Ok(results)
        }).into_box()
    }

    fn insert(&self, value: Vec<u8>, _expiry: u64) -> BoxFuture<()> {
        let inner = self.inner.clone();
        let key = hash_storage_key(&value);

        future::lazy(move || {
            inner.db.put(&key, &value)?;

            Ok(())
        }).into_box()
    }

    fn insert_batch(&self, values: Vec<(Vec<u8>, u64)>) -> BoxFuture<()> {
        let inner = self.inner.clone();

        future::lazy(move || {
            let mut batch = WriteBatch::default();
            for (value, _expiry) in values {
                let key = hash_storage_key(&value);
                batch.put(&key, &value)?;
            }

            inner.db.write(batch)?;

            Ok(())
        }).into_box()
    }

    fn get_keys(&self) -> BoxFuture<Arc<Vec<(H256, u64)>>> {
        let inner = self.inner.clone();

        future::lazy(move || {
            let keys = inner
                .db
                .iterator(IteratorMode::Start)
                .map(|entry| {
                    let key = H256::from(&*entry.0);
                    (key, 0)
                })
                .collect();
            Ok(Arc::new(keys))
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
