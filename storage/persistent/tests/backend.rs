#![feature(test)]

extern crate ekiden_common;
extern crate ekiden_storage_base;
extern crate ekiden_storage_persistent;

extern crate test;

use std::{fs, path::Path};

use test::Bencher;

use ekiden_common::{bytes::H256, futures::Future};
use ekiden_storage_base::{hash_storage_key, InsertOptions, StorageBackend};
use ekiden_storage_persistent::PersistentStorageBackend;

#[test]
fn test_persistent_backend() {
    let db_path = Path::new("test-db");
    let backend = PersistentStorageBackend::new(db_path);
    assert!(!backend.is_err());
    let backend = backend.unwrap();
    let key = hash_storage_key(b"value");

    assert!(backend.get(key).wait().is_err());
    backend
        .insert(b"value".to_vec(), 10, InsertOptions::default())
        .wait()
        .unwrap();
    assert_eq!(backend.get(key).wait(), Ok(b"value".to_vec()));

    assert_eq!(
        backend.get_batch(vec![key, H256::zero(), key]).wait(),
        Ok(vec![Some(b"value".to_vec()), None, Some(b"value".to_vec())]),
    );

    let key_foo = hash_storage_key(b"foo");
    let key_bar = hash_storage_key(b"bar");
    assert!(backend
        .insert_batch(
            vec![(b"foo".to_vec(), 10), (b"bar".to_vec(), 10)],
            InsertOptions::default(),
        )
        .wait()
        .is_ok(),);
    assert_eq!(
        backend.get_batch(vec![key_foo, key_bar]).wait(),
        Ok(vec![Some(b"foo".to_vec()), Some(b"bar".to_vec())]),
    );

    fs::remove_dir_all(db_path).expect("Could not cleanup DB.");
}

#[bench]
fn bench_persistent_speed(b: &mut Bencher) {
    use ekiden_storage_base::StorageBackend;

    let db_path = Path::new("test-db-speed");
    let backend = PersistentStorageBackend::new(db_path);
    assert!(!backend.is_err());
    let backend = backend.unwrap();

    backend
        .insert(b"value".to_vec(), 10, InsertOptions::default())
        .wait()
        .unwrap();

    b.iter(|| {
        backend
            .insert(b"value".to_vec(), 10, InsertOptions::default())
            .wait()
            .unwrap()
    });

    fs::remove_dir_all(db_path).expect("Could not cleanup DB.");
}
