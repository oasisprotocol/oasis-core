extern crate test;

use io_context::Context;

use crate::storage::mkvs::{sync::*, tree::*};

use self::test::Bencher;

const INSERT_ITEMS: usize = 10000;

fn gen_pairs() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut keys: Vec<Vec<u8>> = Vec::new();
    let mut vals: Vec<Vec<u8>> = Vec::new();
    for i in 0..INSERT_ITEMS {
        keys.push(format!("key{}", i).into_bytes());
        vals.push(format!("val{}", i).into_bytes());
    }
    (keys, vals)
}

fn gen_tree() -> (Tree, Vec<Vec<u8>>) {
    let mut tree = Tree::make()
        .with_root_type(RootType::State)
        .new(Box::new(NoopReadSyncer));

    let (keys, vals) = gen_pairs();
    for i in 0..keys.len() {
        tree.insert(Context::background(), keys[i].as_ref(), vals[i].as_ref())
            .expect("insert");
    }

    (tree, keys)
}

#[bench]
fn bench_nonexistent_get(b: &mut Bencher) {
    let (tree, _) = gen_tree();

    b.iter(|| {
        tree.get(Context::background(), b"foo").expect("get");
    });
}

#[bench]
fn bench_existing_scan(b: &mut Bencher) {
    let (tree, keys) = gen_tree();
    let keys_capture = &keys.clone();
    b.iter(|| {
        for k in keys_capture {
            tree.get(Context::background(), k.as_ref()).expect("get");
        }
    });
}

#[bench]
fn bench_single_inserts(b: &mut Bencher) {
    let (keys, vals) = gen_pairs();
    let mut tree = Tree::make()
        .with_root_type(RootType::State)
        .new(Box::new(NoopReadSyncer));

    let mut i = 0;
    b.iter(|| {
        tree.insert(
            Context::background(),
            keys[i % keys.len()].as_ref(),
            vals[i % vals.len()].as_ref(),
        )
        .expect("insert");
        i += 1;
    });
}

#[bench]
fn bench_insert(b: &mut Bencher) {
    let (keys, vals) = gen_pairs();

    b.iter(|| {
        let mut tree = Tree::make()
            .with_root_type(RootType::State)
            .new(Box::new(NoopReadSyncer));

        for i in 0..keys.len() {
            tree.insert(Context::background(), keys[i].as_ref(), vals[i].as_ref())
                .expect("insert");
        }
        tree.commit(Context::background(), Default::default(), 0)
            .expect("commit");
    });
}

fn bench_insert_batch(b: &mut Bencher, num_values: usize, commit: bool) {
    b.iter(|| {
        let mut tree = Tree::make()
            .with_root_type(RootType::State)
            .new(Box::new(NoopReadSyncer));
        for i in 0..num_values {
            let key = format!("key {}", i);
            let value = format!("value {}", i);
            tree.insert(Context::background(), key.as_bytes(), value.as_bytes())
                .expect("insert");
        }
        if commit {
            tree.commit(Context::background(), Default::default(), 0)
                .expect("commit");
        }
    });
}

#[bench]
fn bench_insert_commit_batch_1(b: &mut Bencher) {
    bench_insert_batch(b, 1, true)
}

#[bench]
fn bench_insert_commit_batch_10(b: &mut Bencher) {
    bench_insert_batch(b, 10, true)
}

#[bench]
fn bench_insert_commit_batch_100(b: &mut Bencher) {
    bench_insert_batch(b, 100, true)
}

#[bench]
fn bench_insert_commit_batch_1000(b: &mut Bencher) {
    bench_insert_batch(b, 1000, true)
}

#[bench]
fn bench_insert_no_commit_batch_1(b: &mut Bencher) {
    bench_insert_batch(b, 1, false)
}

#[bench]
fn bench_insert_no_commit_batch_10(b: &mut Bencher) {
    bench_insert_batch(b, 10, false)
}

#[bench]
fn bench_insert_no_commit_batch_100(b: &mut Bencher) {
    bench_insert_batch(b, 100, false)
}

#[bench]
fn bench_insert_no_commit_batch_1000(b: &mut Bencher) {
    bench_insert_batch(b, 1000, false)
}
