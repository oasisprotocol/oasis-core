extern crate base64;
extern crate ekiden_common;
extern crate ekiden_storage_base;
extern crate ekiden_storage_persistent;

use std::collections::HashMap;
use std::fs;

use ekiden_common::bytes::B256;
use ekiden_common::epochtime::local::SystemTimeSource;
use ekiden_common::futures::Future;
use ekiden_storage_base::{hash_storage_key, StorageBackend};
use ekiden_storage_persistent::PersistentStorageBackend;

#[test]
fn test_persistent_backend() {
    let contract_id = B256::zero();
    let backend =
        PersistentStorageBackend::new(contract_id, Box::new(SystemTimeSource {}), HashMap::new());
    assert!(!backend.is_err());
    let backend = backend.unwrap();
    let key = hash_storage_key(b"value");

    assert!(backend.get(key).wait().is_err());
    backend.insert(b"value".to_vec(), 10).wait().unwrap();
    assert_eq!(backend.get(key).wait(), Ok(b"value".to_vec()));

    let db_path = base64::encode(&contract_id);
    fs::remove_dir_all(db_path).expect("Could not cleanup DB.");
}
