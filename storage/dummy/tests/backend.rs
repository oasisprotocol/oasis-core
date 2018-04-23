extern crate ekiden_common;
extern crate ekiden_storage_base;
extern crate ekiden_storage_dummy;

use ekiden_common::futures::Future;
use ekiden_storage_base::StorageBackend;
use ekiden_storage_dummy::DummyStorageBackend;

#[test]
fn test_dummy_backend() {
    let backend = DummyStorageBackend::new();
    let key = StorageBackend::to_key(b"value");

    assert!(backend.get(&key).wait().is_err());
    backend.insert(b"value", 10).wait().unwrap();
    assert_eq!(backend.get(&key).wait(), Ok(b"value".to_vec()));
}
