#![feature(test)]

extern crate test;

extern crate ekiden_db_trusted;

use test::Bencher;

use ekiden_db_trusted::{Database, DatabaseHandle};
use ekiden_db_trusted::ecalls::{db_state_apply, db_state_diff, db_state_get, db_state_set};

/// Populate the database with some dummy state.
fn generate_dummy_state() {
    let mut db = DatabaseHandle::instance();
    db.insert(b"example_key1", &vec![42; 128]);
    db.insert(b"example_key2", &vec![21; 128]);
}

/// Export current database state.
fn export_db_state() -> Vec<u8> {
    let mut state: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut state_length = 0;

    db_state_get(state.as_mut_ptr(), state.capacity(), &mut state_length);

    unsafe {
        state.set_len(state_length);
    }
    assert!(!state.is_empty());

    state
}

/// Benchmark raw database set with a 128-byte value.
#[bench]
fn benchmark_insert_raw128(b: &mut Bencher) {
    b.iter(|| {
        let mut db = DatabaseHandle::instance();
        db.insert(b"example_key", &vec![42; 128]);
    });
}

/// Benchmark raw database get with a 128-byte value.
#[bench]
fn benchmark_get_raw128(b: &mut Bencher) {
    generate_dummy_state();

    b.iter(|| {
        let db = DatabaseHandle::instance();
        assert_eq!(db.get(b"example_key1"), Some(vec![42; 128]));
        assert_eq!(db.get(b"example_key2"), Some(vec![21; 128]));
    });
}

/// Benchmark database export.
#[bench]
fn benchmark_export(b: &mut Bencher) {
    generate_dummy_state();

    b.iter(|| {
        export_db_state();
    });
}

/// Benchmark database import.
#[bench]
fn benchmark_import(b: &mut Bencher) {
    generate_dummy_state();
    let state = export_db_state();

    b.iter(|| {
        db_state_set(state.as_ptr(), state.len());
    });
}

/// Benchmark database diff.
#[bench]
fn benchmark_diff(b: &mut Bencher) {
    generate_dummy_state();
    let old_state = export_db_state();

    {
        let mut db = DatabaseHandle::instance();
        db.insert(b"example_key1", &vec![21; 128]);
    }

    let new_state = export_db_state();

    b.iter(|| {
        let mut diff: Vec<u8> = Vec::with_capacity(64 * 1024);
        let mut diff_length = 0;

        db_state_diff(
            old_state.as_ptr(),
            old_state.len(),
            new_state.as_ptr(),
            new_state.len(),
            diff.as_mut_ptr(),
            diff.capacity(),
            &mut diff_length,
        );

        assert!(diff_length > 0);
    });
}

/// Benchmark database diff apply.
#[bench]
fn benchmark_apply(b: &mut Bencher) {
    generate_dummy_state();
    let old_state = export_db_state();

    {
        let mut db = DatabaseHandle::instance();
        db.insert(b"example_key1", &vec![21; 128]);
    }

    let new_state = export_db_state();

    // Generate diff.
    let mut diff: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut diff_length = 0;

    db_state_diff(
        old_state.as_ptr(),
        old_state.len(),
        new_state.as_ptr(),
        new_state.len(),
        diff.as_mut_ptr(),
        diff.capacity(),
        &mut diff_length,
    );

    unsafe {
        diff.set_len(diff_length);
    }

    b.iter(|| {
        let mut output: Vec<u8> = Vec::with_capacity(64 * 1024);
        let mut output_length = 0;

        db_state_apply(
            old_state.as_ptr(),
            old_state.len(),
            diff.as_ptr(),
            diff.len(),
            output.as_mut_ptr(),
            output.capacity(),
            &mut output_length,
        );
    });
}
