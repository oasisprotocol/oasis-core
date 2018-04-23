//! Ekiden storage interface.
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ekiden_common::error::{Error, Result};
use ekiden_common::futures::{future, BoxFuture};
use ekiden_common::rlp::{self, Rlp};
use ekiden_common::serializer::Serializable;
use ekiden_storage_base::StorageBackend;

use sled::{ConfigBuilder, Tree};
use tar::{Archive, Builder};

struct PersistentStorageBackendInner {
    storage: Tree,
    backing: String,
    current_epoch: usize,
}

pub struct PersistentStorageBackend {
    inner: Arc<Mutex<PersistentStorageBackendInner>>,
}

impl PersistentStorageBackend {
    pub fn new(path: &str) -> Result<Self> {
        let path = path.to_owned();
        let mut pb = PathBuf::from(&path);
        if !pb.as_path().exists() {
            fs::create_dir(&path)?;
        }
        pb.push("db.sled");
        let config = ConfigBuilder::default().path(pb.as_path());

        Ok(Self {
            inner: Arc::new(Mutex::new(PersistentStorageBackendInner {
                storage: Tree::start(config.build()).unwrap(),
                backing: path,
                current_epoch: 0,
            })),
        })
    }

    // TODO: is this the right interface, or should we have knoweldge of the ID of the contract
    // the storage backend is being created for.
    pub fn read_from(instance_id: &str, reader: &mut Read) -> Result<Self> {
        // Database is serialized with a tar archive because it covers multiple files.
        let mut ar = Archive::new(reader);
        ar.unpack(instance_id)?;
        PersistentStorageBackend::new(instance_id)
    }
}

/// StorageBackend defines the actual storage interface of getting and setting data.
impl StorageBackend for PersistentStorageBackend {
    fn get(&self, key: &[u8]) -> BoxFuture<Vec<u8>> {
        let inner = self.inner.clone();
        let key = key.to_owned();

        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            match inner.storage.get(&key) {
                Ok(Some(vec)) => Ok(vec),
                _ => Err(Error::new("no key found")),
            }
        }))
    }

    fn insert(&self, value: &[u8], expiry: usize) -> BoxFuture<()> {
        let inner = self.inner.clone();
        let value = value.to_owned();

        let mut key = Self::to_key(&value);
        let expiry = expiry.to_owned();

        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            let expiry_key = format!("expire_{}", inner.current_epoch + expiry).into_bytes();

            // Add this item into the expiry accounting.
            let expiry_value = match inner.storage.get(&expiry_key) {
                Ok(Some(val)) => {
                    let list = Rlp::new(&val);
                    assert!(list.is_list());
                    let mut list: Vec<u8> = list.as_list();
                    list.append(&mut key);
                    rlp::encode_list(&list).into_vec()
                }
                _ => rlp::encode_list::<Vec<u8>, _>(vec![key.clone()].as_slice()).into_vec(),
            };
            inner.storage.set(expiry_key, expiry_value)?;

            Ok(inner.storage.set(key.to_vec(), value)?)
        }))
    }
}

/// PersistentStorageBackend can write to a stream for transition to other nodes.
impl Serializable for PersistentStorageBackend {
    // TODO: should be a future, ideally.
    // TODO: shouldn't persist keys marked as expiring.
    fn write_to(&self, writer: &mut Write) -> Result<usize> {
        let inner = self.inner.clone();
        let inner = inner.lock().unwrap();
        inner.storage.flush()?;

        let mut ar = Builder::new(writer);
        println!("appending '{}'", &inner.backing);
        ar.append_dir_all(".", &inner.backing)?;
        println!("Appended.");
        ar.finish()?;
        println!("Finished.");
        // TODO: actual size needed?
        Ok(0)
    }
}
