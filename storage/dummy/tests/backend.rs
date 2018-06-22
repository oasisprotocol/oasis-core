#![feature(test)]

extern crate ekiden_common;
extern crate ekiden_storage_base;
extern crate ekiden_storage_dummy;

extern crate test;

use ekiden_common::futures::Future;
use ekiden_storage_base::hash_storage_key;
use ekiden_storage_dummy::DummyStorageBackend;

use test::Bencher;

#[test]
fn test_dummy_backend() {
    // Import the StorageBackend trait to use the backend get/insert.
    use ekiden_storage_base::StorageBackend;

    let backend = DummyStorageBackend::new();
    let key = hash_storage_key(b"value");

    assert!(backend.get(key).wait().is_err());
    backend.insert(b"value".to_vec(), 10).wait().unwrap();
    assert_eq!(backend.get(key).wait(), Ok(b"value".to_vec()));
}

#[test]
fn test_dummy_storage_mapper() {
    // Import the StorageMapper trait to use the mapper get/insert.
    use ekiden_storage_base::StorageMapper;

    let backend = DummyStorageBackend::new();
    let key = hash_storage_key(b"value");

    assert!(backend.get(key).wait().is_err());
    let key_result = backend.insert(b"value".to_vec(), 10).wait().unwrap();
    assert_eq!(key, key_result);
    assert_eq!(backend.get(key).wait(), Ok(b"value".to_vec()));
}

#[bench]
fn bench_dummy_speed(b: &mut Bencher) {
    use ekiden_storage_base::StorageBackend;

    let backend = DummyStorageBackend::new();
    let _key = hash_storage_key(b"value");

    b.iter(|| backend.insert(b"value".to_vec(), 10).wait().unwrap())
}
