extern crate ekiden_common;
extern crate ekiden_storage_base;
extern crate ekiden_storage_persistent;

use std::collections::HashMap;
use std::fs;

use ekiden_common::epochtime::local::SystemTimeSource;
use ekiden_common::futures::Future;
use ekiden_storage_base::{hash_storage_key, StorageBackend};
use ekiden_storage_persistent::PersistentStorageBackend;

#[test]
fn test_persistent_backend() {
    let mut config = HashMap::new();
    let db_path = String::from("./db/");
    config.insert(
        ekiden_storage_persistent::PERSISTENT_STORAGE_BASE_PATH.to_owned(),
        db_path.to_owned(),
    );
    let backend = PersistentStorageBackend::new(Box::new(SystemTimeSource {}), config);
    assert!(!backend.is_err());
    let backend = backend.unwrap();
    let key = hash_storage_key(b"value");

    assert!(backend.get(key).wait().is_err());
    backend.insert(b"value".to_vec(), 10).wait().unwrap();
    assert_eq!(backend.get(key).wait(), Ok(b"value".to_vec()));

    fs::remove_dir_all(db_path).expect("Could not cleanup DB.");
}
