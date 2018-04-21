//! Ekiden storage interface
use std::error::Error as stdError;
use std::fs::File;
use std::io::{copy, Read, Write};
use std::path::{Path};
use std::sync::{Arc, Mutex};

use ekiden_common::error::{Error, Result};
use ekiden_common::futures::{future, BoxFuture};
use ekiden_common::serializer::{Serializable};
use ekiden_storage_base::StorageBackend;

use sled::{ConfigBuilder, Tree};

struct PersistentStorageBackendInner {
    storage: Tree,
    backing: File,
}

pub struct PersistentStorageBackend {
  inner: Arc<Mutex<PersistentStorageBackendInner>>,
}

impl PersistentStorageBackend {
  pub fn new(path: &str) -> Result<Self> {
    let config = ConfigBuilder::default()
        .path(path);
    let path = String::from(path);
    let backing = File::open(Path::new(&path))?;
    Ok(Self {
        inner: Arc::new(Mutex::new(PersistentStorageBackendInner{
            storage: Tree::start(config.build()).unwrap(),
            backing: backing,
        })),
    })
  }

  // TODO: is this the right interface, or should we have knoweldge of the ID of the contract
  // the storage backend is being created for.
  fn read_from(instance_id: &str, reader: &mut Read) -> Result<Self> {
      let path = Path::new(instance_id);
      let mut file: File = File::open(path)?;
      copy(reader, &mut file)?;
      let path = match path.to_str() {
          Some(p) => p,
          None => return Err(Error::new("Instance unusable as file")),
      };
      PersistentStorageBackend::new(path)
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

  fn insert(&self, value: &[u8]) -> BoxFuture<()> {
      let inner = self.inner.clone();
      let value = value.to_owned();

      let key = vec![];

      Box::new(future::lazy(move || {
          let inner = inner.lock().unwrap();
          Ok(inner.storage.set(key, value)?)
      }))
  }
}

/// PersistentStorageBackend's serialize for transition to other nodes.
impl Serializable for PersistentStorageBackend {
    fn write_to(&self, writer: &mut Write) -> Result<usize> {
        let inner = self.inner.clone();
        let inner = inner.lock().unwrap();
        inner.storage.flush()?;

        match copy(&mut inner.backing, writer) {
            Ok(n) => Ok(n as usize),
            Err(e) => Err(Error::new(e.description())),
        }
    }
}
