extern crate ekiden_common;
extern crate ekiden_storage_base;
extern crate ekiden_storage_persistent;
extern crate mktemp;

use mktemp::Temp;
use std::fs::{self, File};

use ekiden_common::futures::Future;
use ekiden_common::serializer::Serializable;
use ekiden_storage_base::StorageBackend;
use ekiden_storage_persistent::PersistentStorageBackend;

#[test]
fn test_persistent_backend() {
    let workspace = Temp::new_dir().unwrap();
    let path_buf = workspace.to_path_buf();
    let backend = PersistentStorageBackend::new(path_buf.to_str().unwrap());
    assert!(!backend.is_err());
    let backend = backend.unwrap();
    let key = PersistentStorageBackend::hash_key(b"value");

    assert!(backend.get(&key).wait().is_err());
    backend.insert(b"value", 10).wait().unwrap();
    assert_eq!(backend.get(&key).wait(), Ok(b"value".to_vec()));
}

#[test]
fn test_persistent_backend_serialization() {
    let workspace = Temp::new_dir().unwrap();
    let path_buf = workspace.to_path_buf();

    let mut be = path_buf.clone();
    be.push("test2");
    let backend = PersistentStorageBackend::new(be.to_str().unwrap());
    assert!(!backend.is_err());
    let backend = backend.unwrap();
    let key = PersistentStorageBackend::hash_key(b"value");

    backend.insert(b"value", 10).wait().unwrap();
    assert_eq!(backend.get(&key).wait(), Ok(b"value".to_vec()));

    // Serialize to a file.
    let mut file = path_buf.clone();
    file.push("serial.bin");
    let mut serialized = File::create(file.to_str().unwrap()).expect("could not create file.");
    match backend.write_to(&mut serialized) {
        Ok(_) => (),
        Err(e) => panic!("write_to err: {}", e),
    };

    fs::remove_dir_all(be.to_str().unwrap()).expect("Could not cleanup DB.");

    // Restore to a new instance.
    let mut deserial = File::open(file.to_str().unwrap()).expect("file not created.");
    // TODO: currently, sled requires exact match of instance ID (relative path of DB).
    let new_backend = PersistentStorageBackend::read_from(be.to_str().unwrap(), &mut deserial);
    match new_backend {
        Ok(_) => (),
        Err(e) => panic!("{}", e),
    };
    let new_backend = new_backend.unwrap();

    assert_eq!(new_backend.get(&key).wait(), Ok(b"value".to_vec()));
}
