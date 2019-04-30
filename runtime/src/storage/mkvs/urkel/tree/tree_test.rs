use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{cache::*, sync::*, tree::*},
};

const INSERT_ITEMS: usize = 10000;
const ALL_ITEMS_ROOT: &str = "fecf46042f82fd1ec38c9f5ee40f941d8a147976d51b59f4c16bc5c0467c7f4f";

fn generate_key_value_pairs() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(INSERT_ITEMS);
    let mut values: Vec<Vec<u8>> = Vec::with_capacity(INSERT_ITEMS);

    for i in 0..INSERT_ITEMS {
        keys.push(format!("key {}", i).into_bytes());
        values.push(format!("value {}", i).into_bytes());
    }

    (keys, values)
}

#[test]
fn test_basic() {
    let mut tree = UrkelTree::make()
        .new(Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let key_zero = b"foo";
    let value_zero = b"bar";
    let value_zero_alt = b"baz";
    let key_one = b"moo";
    let value_one = b"foo";
    let value_one_alt = b"boo";

    // Insert two keys and check committed tree.
    tree.insert(key_zero, value_zero).expect("insert");
    let value = tree.get(key_zero).expect("get").expect("get_some");
    assert_eq!(value.as_slice(), value_zero);

    tree.insert(key_zero, value_zero).expect("insert");
    let value = tree.get(key_zero).expect("get").expect("get_some");
    assert_eq!(value.as_slice(), value_zero);

    let (log, hash) = tree.commit().expect("commit");
    assert_eq!(
        format!("{:?}", hash),
        "f83b5a082f1d05c31aadc863c44df9b2b322b570e47e7528faf484ca2084ad08"
    );
    assert_eq!(
        log,
        [LogEntry {
            key: key_zero.to_vec(),
            value: Some(value_zero.to_vec()),
        }]
        .to_vec()
    );
    assert_eq!(log[0].kind(), LogEntryKind::Insert);

    // Check overwriting modifications.
    tree.insert(key_one, value_one).expect("insert");
    let value = tree.get(key_one).expect("get").expect("get_some");
    assert_eq!(value.as_slice(), value_one);

    tree.insert(key_zero, value_zero_alt).expect("insert");
    let value = tree.get(key_zero).expect("get").expect("get_some");
    assert_eq!(value.as_slice(), value_zero_alt);
    let value = tree.get(key_one).expect("get").expect("get_some");
    assert_eq!(value.as_slice(), value_one);

    tree.remove(key_one).expect("remove");
    assert_eq!(None, tree.get(key_one).expect("get"));
    let value = tree.get(key_zero).expect("get").expect("get_some");
    assert_eq!(value.as_slice(), value_zero_alt);

    tree.insert(key_one, value_one_alt).expect("insert");
    let value = tree.get(key_zero).expect("get").expect("get_some");
    assert_eq!(value.as_slice(), value_zero_alt);
    let value = tree.get(key_one).expect("get").expect("get_some");
    assert_eq!(value.as_slice(), value_one_alt);

    tree.insert(key_zero, value_zero).expect("insert");
    tree.insert(key_one, value_one).expect("insert");

    // Tree now has key_zero and key_one and should hash as if the mangling didn't happen.
    let (log, hash) = tree.commit().expect("commit");
    assert_eq!(
        format!("{:?}", hash),
        "839bb81bff8bc8bb0bee99405a094bcb1d983f9f830cc3e3475e07cb7da4b90c"
    );
    assert_eq!(
        log,
        [
            LogEntry {
                key: key_one.to_vec(),
                value: Some(value_one.to_vec()),
            },
            LogEntry {
                key: key_zero.to_vec(),
                value: Some(value_zero.to_vec()),
            }
        ]
        .to_vec()
    );
    assert_eq!(log[0].kind(), LogEntryKind::Insert);

    tree.remove(key_one).expect("remove");
    assert_eq!(true, tree.get(key_one).expect("get").is_none());

    let (log, hash) = tree.commit().expect("commit");
    assert_eq!(
        format!("{:?}", hash),
        "f83b5a082f1d05c31aadc863c44df9b2b322b570e47e7528faf484ca2084ad08"
    );
    assert_eq!(
        log,
        [LogEntry {
            key: key_one.to_vec(),
            value: None,
        }]
        .to_vec()
    );
    assert_eq!(log[0].kind(), LogEntryKind::Delete);
    tree.remove(key_zero).expect("remove");
}

#[test]
fn test_insert_commit_batch() {
    let mut tree = UrkelTree::make()
        .new(Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");

        let value = tree
            .get(keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());
    }

    let (_, hash) = tree.commit().expect("commit");
    assert_eq!(format!("{:?}", hash), ALL_ITEMS_ROOT);
}

#[test]
fn test_insert_commit_each() {
    let mut tree = UrkelTree::make()
        .new(Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");

        let value = tree
            .get(keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());

        tree.commit().expect("commit");
    }

    let (_, hash) = tree.commit().expect("commit");
    assert_eq!(format!("{:?}", hash), ALL_ITEMS_ROOT);
}

#[test]
fn test_remove() {
    let mut tree = UrkelTree::make()
        .new(Box::new(NoopReadSyncer {}))
        .expect("new_tree");
    let mut roots: Vec<Hash> = Vec::new();

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");

        let value = tree
            .get(keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());

        let (_, hash) = tree.commit().expect("commit");
        roots.push(hash);
    }

    assert_eq!(format!("{:?}", roots[roots.len() - 1]), ALL_ITEMS_ROOT);

    for i in (1..keys.len()).rev() {
        tree.remove(keys[i].as_slice()).expect("remove");

        let (_, hash) = tree.commit().expect("commit");
        assert_eq!(hash, roots[i - 1]);
    }

    tree.remove(keys[0].as_slice()).expect("remove");
    let (_, hash) = tree.commit().expect("commit");
    assert_eq!(hash, Hash::empty_hash());
}

#[test]
fn test_syncer_basic_no_prefetch() {
    let mut tree = UrkelTree::make()
        .new(Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");
    }

    let (_, hash) = tree.commit().expect("commit");
    assert_eq!(format!("{:?}", hash), ALL_ITEMS_ROOT);

    // Create a "remote" tree that talks to the original tree via the
    // syncer interface. First try with no prefetching and then with
    // prefetching.

    let stats = StatsCollector::new(Box::new(tree));
    let remote_tree = UrkelTree::make()
        .with_root(hash)
        .new(Box::new(stats))
        .expect("with_root");

    for i in 0..keys.len() {
        let value = remote_tree
            .get(keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());
    }

    {
        let cache = remote_tree.cache.borrow();
        let stats = cache
            .get_read_syncer()
            .as_any()
            .downcast_ref::<StatsCollector>()
            .expect("stats");
        assert_eq!(0, stats.subtree_fetches, "subtree fetches (no prefetch)");
        assert_eq!(0, stats.node_fetches, "node fetches (no prefetch)");
        assert_eq!(12056, stats.path_fetches, "path fetches (no prefetch)");
        assert_eq!(0, stats.value_fetches, "value fetches (no prefetch)");
    }
}

#[test]
fn test_syncer_basic_with_prefetch() {
    let mut tree = UrkelTree::make()
        .new(Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");
    }

    let (_, hash) = tree.commit().expect("commit");
    assert_eq!(format!("{:?}", hash), ALL_ITEMS_ROOT);

    // Create a "remote" tree that talks to the original tree via the
    // syncer interface. First try with no prefetching and then with
    // prefetching.

    let stats = StatsCollector::new(Box::new(tree));
    let remote_tree = UrkelTree::make()
        .with_root(hash)
        .with_prefetch_depth(10)
        .new(Box::new(stats))
        .expect("with_root");

    for i in 0..keys.len() {
        let value = remote_tree
            .get(keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());
    }

    {
        let cache = remote_tree.cache.borrow();
        let stats = cache
            .get_read_syncer()
            .as_any()
            .downcast_ref::<StatsCollector>()
            .expect("stats");
        assert_eq!(1, stats.subtree_fetches, "subtree fetches (with prefetch)");
        assert_eq!(0, stats.node_fetches, "node fetches (with prefetch)");
        assert_eq!(12158, stats.path_fetches, "path fetches (with prefetch)");
        assert_eq!(0, stats.value_fetches, "value fetches (with prefetch)");
    }
}

#[test]
fn test_value_eviction() {
    let mut tree = UrkelTree::make()
        .with_capacity(0, 1024)
        .new(Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");
    }
    tree.commit().expect("commit");

    let stats = tree.stats(0);
    assert_eq!(
        14331, stats.cache.internal_node_count,
        "cache.internal_node_count"
    );
    assert_eq!(10000, stats.cache.leaf_node_count, "cache.leaf_node_count");
    // Only a subset of the leaf values should remain in cache.
    assert_eq!(1021, stats.cache.leaf_value_size, "cache.leaf_value_size");
}

#[test]
fn test_node_eviction() {
    let mut tree = UrkelTree::make()
        .with_capacity(1000, 0)
        .new(Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");
    }
    tree.commit().expect("commit");

    let stats = tree.stats(0);
    // Only a subset of nodes should remain in cache.
    assert_eq!(
        590, stats.cache.internal_node_count,
        "cache.internal_node_count"
    );
    assert_eq!(410, stats.cache.leaf_node_count, "cache.leaf_node_count");
    // Only a subset of the leaf values should remain in cache.
    assert_eq!(4050, stats.cache.leaf_value_size, "cache.leaf_value_size");
}

#[test]
fn test_debug_dump() {
    let mut tree = UrkelTree::make()
        .new(Box::new(NoopReadSyncer {}))
        .expect("new_tree");
    tree.insert(b"foo 1", b"bar 1").expect("insert");
    tree.insert(b"foo 2", b"bar 2").expect("insert");
    tree.insert(b"foo 3", b"bar 3").expect("insert");

    let mut output: Vec<u8> = Vec::new();
    tree.dump(&mut output).expect("dump");
    assert!(output.len() > 0);
}

#[test]
fn test_debug_stats() {
    let mut tree = UrkelTree::make()
        .new(Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");
    }

    let stats = tree.stats(0);
    assert_eq!(28, stats.max_depth, "max_depth");
    assert_eq!(14331, stats.internal_node_count, "internal_node_count");
    assert_eq!(10000, stats.leaf_node_count, "leaf_node_count");
    assert_eq!(98890, stats.leaf_value_size, "leaf_value_size");
    assert_eq!(4332, stats.dead_node_count, "dead_node_count");
    // Cached node counts will update on commit.
    assert_eq!(
        0, stats.cache.internal_node_count,
        "cache.internal_node_count"
    );
    assert_eq!(0, stats.cache.leaf_node_count, "cache.leaf_node_count");
    // Cached leaf value size will update on commit.
    assert_eq!(0, stats.cache.leaf_value_size, "cache.leaf_value_size");

    tree.commit().expect("commit");

    let stats = tree.stats(0);
    assert_eq!(28, stats.max_depth, "max_depth");
    assert_eq!(14331, stats.internal_node_count, "internal_node_count");
    assert_eq!(10000, stats.leaf_node_count, "leaf_node_count");
    assert_eq!(98890, stats.leaf_value_size, "leaf_value_size");
    assert_eq!(4332, stats.dead_node_count, "dead_node_count");
    assert_eq!(
        14331, stats.cache.internal_node_count,
        "cache.internal_node_count"
    );
    assert_eq!(10000, stats.cache.leaf_node_count, "cache.leaf_node_count");
    assert_eq!(98890, stats.cache.leaf_value_size, "cache.leaf_value_size");
}
