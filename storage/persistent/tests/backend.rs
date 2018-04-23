extern crate ekiden_common;
extern crate ekiden_storage_base;
extern crate ekiden_storage_persistent;

use std::fs::{self, File};

use ekiden_common::futures::Future;
use ekiden_common::serializer::Serializable;
use ekiden_storage_base::StorageBackend;
use ekiden_storage_persistent::PersistentStorageBackend;

#[test]
fn test_persistent_backend() {
    let backend = PersistentStorageBackend::new("test.sled");
    assert!(!backend.is_err());
    let backend = backend.unwrap();
    let key = PersistentStorageBackend::to_key(b"value");

    assert!(backend.get(&key).wait().is_err());
    backend.insert(b"value", 10).wait().unwrap();
    assert_eq!(backend.get(&key).wait(), Ok(b"value".to_vec()));

    fs::remove_dir_all("test.sled").expect("Could not cleanup DB.");
}

#[test]
fn test_persistent_backend_serialization() {
    let backend = PersistentStorageBackend::new("test2");
    assert!(!backend.is_err());
    let backend = backend.unwrap();
    let key = PersistentStorageBackend::to_key(b"value");

    backend.insert(b"value", 10).wait().unwrap();
    assert_eq!(backend.get(&key).wait(), Ok(b"value".to_vec()));

    // Serialize to a file.
    let mut serialized = File::create("serial.bin").expect("could not create file.");
    match backend.write_to(&mut serialized) {
        Ok(_) => (),
        Err(e) => panic!("write_to err: {}", e),
    };

    fs::remove_dir_all("test2").expect("Could not cleanup DB.");

    // Restore to a new instance.
    let mut deserial = File::open("serial.bin").expect("file not created.");
    // TODO: currently, sled requires exact match of instance ID (relative path of DB).
    let new_backend = PersistentStorageBackend::read_from("test2", &mut deserial);
    match new_backend {
        Ok(_) => (),
        Err(e) => panic!("{}", e),
    };
    let new_backend = new_backend.unwrap();

    assert_eq!(new_backend.get(&key).wait(), Ok(b"value".to_vec()));

    fs::remove_file("serial.bin").expect("Could not cleanup DB.");
    fs::remove_dir_all("test2").expect("Could not cleanup DB.");
}
