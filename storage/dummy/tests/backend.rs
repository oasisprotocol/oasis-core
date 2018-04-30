extern crate ekiden_common;
extern crate ekiden_storage_base;
extern crate ekiden_storage_dummy;

use ekiden_common::futures::Future;
use ekiden_storage_base::StorageBackend;
use ekiden_storage_dummy::DummyStorageBackend;

#[test]
fn test_dummy_backend() {
    let backend = DummyStorageBackend::new();

    assert!(backend.get(b"namespace", b"key").wait().is_err());
    backend
        .insert(b"namespace", b"key", b"value")
        .wait()
        .unwrap();
    assert_eq!(
        backend.get(b"namespace", b"key").wait(),
        Ok(b"value".to_vec())
    );
    backend.remove(b"namespace", b"key").wait().unwrap();
    assert!(backend.get(b"namespace", b"key").wait().is_err());
}
