use io_context::Context;
use std::{collections::HashSet, iter::FromIterator};

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::{
        urkel::{cache::*, sync::*, tree::*},
        LogEntry, LogEntryKind,
    },
};

const INSERT_ITEMS: usize = 1000;
const ALL_ITEMS_ROOT: &str = "67774198b787b4846f67f1cfd1715b4e94d1a75f6caeda08635f8a03932f3413";

const LONG_KEY: &str = "Unlock the potential of your data without compromising security or privacy";
const LONG_VALUE: &str = "The platform that puts data privacy first. From sharing medical records, to analyzing personal financial information, to training machine learning models, the Oasis platform supports applications that use even the most sensitive data without compromising privacy or performance.";
const ALL_LONG_ITEMS_ROOT: &str =
    "0a80a0cf285f9eedec0339372c0ae25190ed75809a0799ab75a593d783ddef00";

fn generate_key_value_pairs_ex(prefix: String, count: usize) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(count);
    let mut values: Vec<Vec<u8>> = Vec::with_capacity(count);

    for i in 0..count {
        keys.push(format!("{}key {}", prefix, i).into_bytes());
        values.push(format!("{}value {}", prefix, i).into_bytes());
    }

    (keys, values)
}
fn generate_key_value_pairs() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    generate_key_value_pairs_ex("".to_string(), INSERT_ITEMS)
}

fn generate_long_key_value_pairs() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(LONG_KEY.len());
    let mut values: Vec<Vec<u8>> = Vec::with_capacity(LONG_KEY.len());

    for i in 0..LONG_KEY.len() {
        keys.push(LONG_KEY[0..i + 1].to_string().into_bytes());
        values.push(LONG_VALUE.to_string().into_bytes());
    }

    (keys, values)
}

#[test]
fn test_basic() {
    let mut tree = UrkelTree::make()
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let key_zero = b"foo";
    let value_zero = b"bar";
    let value_zero_alt = b"baz";
    let key_one = b"moo";
    let value_one = b"foo";
    let value_one_alt = b"boo";

    // Insert two keys and check committed tree.
    assert_eq!(
        tree.insert(Context::background(), key_zero, value_zero)
            .expect("insert"),
        None
    );
    let value = tree
        .get(Context::background(), key_zero)
        .expect("get")
        .expect("get_some");
    assert_eq!(value.as_slice(), value_zero);

    assert_eq!(
        tree.insert(Context::background(), key_zero, value_zero)
            .expect("insert")
            .expect("insert_some")
            .as_slice(),
        value_zero
    );
    let value = tree
        .get(Context::background(), key_zero)
        .expect("get")
        .expect("get_some");
    assert_eq!(value.as_slice(), value_zero);

    let (log, hash) =
        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
    assert_eq!(
        format!("{:?}", hash),
        "c86e7119b52682fea21319c9c747e2197012b49f5050fce5e4aa82e5ced36236"
    );
    assert_eq!(
        log,
        [LogEntry {
            key: key_zero.to_vec(),
            value: value_zero.to_vec(),
        }]
        .to_vec()
    );
    assert_eq!(log[0].kind(), LogEntryKind::Insert);

    // Check overwriting modifications.
    assert_eq!(
        tree.insert(Context::background(), key_one, value_one)
            .expect("insert"),
        None
    );
    let value = tree
        .get(Context::background(), key_one)
        .expect("get")
        .expect("get_some");
    assert_eq!(value.as_slice(), value_one);

    assert_eq!(
        tree.insert(Context::background(), key_zero, value_zero_alt)
            .expect("insert")
            .expect("insert_some")
            .as_slice(),
        value_zero
    );
    let value = tree
        .get(Context::background(), key_zero)
        .expect("get")
        .expect("get_some");
    assert_eq!(value.as_slice(), value_zero_alt);
    let value = tree
        .get(Context::background(), key_one)
        .expect("get")
        .expect("get_some");
    assert_eq!(value.as_slice(), value_one);

    assert_eq!(
        tree.remove(Context::background(), key_one)
            .expect("remove")
            .expect("remove_some")
            .as_slice(),
        value_one
    );
    assert_eq!(
        tree.remove(Context::background(), key_one).expect("remove"),
        None
    );
    assert_eq!(None, tree.get(Context::background(), key_one).expect("get"));
    let value = tree
        .get(Context::background(), key_zero)
        .expect("get")
        .expect("get_some");
    assert_eq!(value.as_slice(), value_zero_alt);

    assert_eq!(
        tree.insert(Context::background(), key_one, value_one_alt)
            .expect("insert"),
        None
    );
    let value = tree
        .get(Context::background(), key_zero)
        .expect("get")
        .expect("get_some");
    assert_eq!(value.as_slice(), value_zero_alt);
    let value = tree
        .get(Context::background(), key_one)
        .expect("get")
        .expect("get_some");
    assert_eq!(value.as_slice(), value_one_alt);

    assert_eq!(
        tree.insert(Context::background(), key_zero, value_zero)
            .expect("insert")
            .expect("insert_some")
            .as_slice(),
        value_zero_alt
    );
    assert_eq!(
        tree.insert(Context::background(), key_one, value_one)
            .expect("insert")
            .expect("insert_some")
            .as_slice(),
        value_one_alt
    );

    // Tree now has key_zero and key_one and should hash as if the mangling didn't happen.
    let (log, hash) =
        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
    assert_eq!(
        format!("{:?}", hash),
        "573e3d24a5e6cf48a390910c31c7166aa40414037380bc77d648b3967b1e124f"
    );
    // Order of transactions in writelog is arbitrary.
    assert_eq!(
        HashSet::<LogEntry>::from_iter(log.clone().into_iter()),
        HashSet::<LogEntry>::from_iter(
            [
                LogEntry {
                    key: key_one.to_vec(),
                    value: value_one.to_vec(),
                },
                LogEntry {
                    key: key_zero.to_vec(),
                    value: value_zero.to_vec(),
                }
            ]
            .to_vec()
            .into_iter()
        )
    );
    assert_eq!(log[0].kind(), LogEntryKind::Insert);
    assert_eq!(log[1].kind(), LogEntryKind::Insert);

    tree.remove(Context::background(), key_one).expect("remove");
    assert_eq!(
        true,
        tree.get(Context::background(), key_one)
            .expect("get")
            .is_none()
    );

    let (log, hash) =
        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
    assert_eq!(
        format!("{:?}", hash),
        "c86e7119b52682fea21319c9c747e2197012b49f5050fce5e4aa82e5ced36236"
    );
    assert_eq!(
        log,
        [LogEntry {
            key: key_one.to_vec(),
            value: Vec::new(),
        }]
        .to_vec()
    );
    assert_eq!(log[0].kind(), LogEntryKind::Delete);
    tree.remove(Context::background(), key_zero)
        .expect("remove");
}

#[test]
fn test_long_keys() {
    let mut tree = UrkelTree::make()
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    // First insert keys 0..n and remove them in order n..0.
    let mut roots: Vec<Hash> = Vec::new();
    let (keys, values) = generate_long_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(
            Context::background(),
            keys[i].as_slice(),
            values[i].as_slice(),
        )
        .expect("insert");

        let (_, hash) = UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0)
            .expect("commit");
        roots.push(hash);
    }

    for i in 0..keys.len() {
        let value = tree
            .get(Context::background(), keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());
    }

    assert_eq!(format!("{:?}", roots[roots.len() - 1]), ALL_LONG_ITEMS_ROOT);

    for i in (1..keys.len()).rev() {
        tree.remove(Context::background(), keys[i].as_slice())
            .expect("remove");

        assert_eq!(
            None,
            tree.get(Context::background(), keys[i].as_slice())
                .expect("get")
        );

        let (_, hash) = UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0)
            .expect("commit");
        assert_eq!(hash, roots[i - 1]);
    }

    tree.remove(Context::background(), keys[0].as_slice())
        .expect("remove");

    let (_, hash) =
        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
    assert_eq!(hash, Hash::empty_hash());
}

#[test]
fn test_empty_keys() {
    let mut tree = UrkelTree::make()
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    fn test_empty_key(tree: &mut UrkelTree) {
        let empty_key = b"";
        let empty_value = b"empty value";

        tree.insert(Context::background(), empty_key, empty_value)
            .expect("insert");

        let value = tree
            .get(Context::background(), empty_key)
            .expect("get")
            .expect("get_some");
        assert_eq!(empty_value, value.as_slice());

        tree.remove(Context::background(), empty_key)
            .expect("remove");

        assert_eq!(
            None,
            tree.get(Context::background(), empty_key).expect("get")
        );
    }

    fn test_zeroth_discriminator_bit(tree: &mut UrkelTree) {
        let key1 = &[0x7f as u8, 0xab];
        let key2 = &[0xff as u8, 0xab];
        let value1 = b"value 1";
        let value2 = b"value 2";

        tree.insert(Context::background(), key1, value1)
            .expect("insert");
        tree.insert(Context::background(), key2, value2)
            .expect("insert");

        let value = tree
            .get(Context::background(), key1)
            .expect("get")
            .expect("get_some");
        assert_eq!(value1, value.as_slice());
        let value = tree
            .get(Context::background(), key2)
            .expect("get")
            .expect("get_some");
        assert_eq!(value2, value.as_slice());

        tree.remove(Context::background(), key1).expect("remove");
        assert_eq!(None, tree.get(Context::background(), key1).expect("get"));

        tree.remove(Context::background(), key2).expect("remove");
        assert_eq!(None, tree.get(Context::background(), key2).expect("get"));
    }

    test_empty_key(&mut tree);
    test_zeroth_discriminator_bit(&mut tree);

    // First insert keys 0..n and remove them in order n..0.
    let mut roots: Vec<Hash> = Vec::new();
    let (keys, values) = generate_long_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(
            Context::background(),
            keys[i].as_slice(),
            values[i].as_slice(),
        )
        .expect("insert");

        test_empty_key(&mut tree);
        test_zeroth_discriminator_bit(&mut tree);

        let (_, hash) = UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0)
            .expect("commit");
        roots.push(hash);
    }

    for i in 0..keys.len() {
        let value = tree
            .get(Context::background(), keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());
    }

    for i in (1..keys.len()).rev() {
        tree.remove(Context::background(), keys[i].as_slice())
            .expect("remove");

        assert_eq!(
            None,
            tree.get(Context::background(), keys[i].as_slice())
                .expect("get")
        );

        test_empty_key(&mut tree);
        test_zeroth_discriminator_bit(&mut tree);

        let (_, hash) = UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0)
            .expect("commit");
        assert_eq!(hash, roots[i - 1]);
    }

    tree.remove(Context::background(), keys[0].as_slice())
        .expect("remove");

    test_empty_key(&mut tree);
    test_zeroth_discriminator_bit(&mut tree);

    let (_, hash) =
        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
    assert_eq!(hash, Hash::empty_hash());
}

#[test]
fn test_insert_commit_batch() {
    let mut tree = UrkelTree::make()
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(
            Context::background(),
            keys[i].as_slice(),
            values[i].as_slice(),
        )
        .expect("insert");

        let value = tree
            .get(Context::background(), keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());
    }

    let (_, hash) =
        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
    assert_eq!(format!("{:?}", hash), ALL_ITEMS_ROOT);
}

#[test]
fn test_insert_commit_each() {
    let mut tree = UrkelTree::make()
        .with_capacity(0, 0)
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(
            Context::background(),
            keys[i].as_slice(),
            values[i].as_slice(),
        )
        .expect("insert");

        let value = tree
            .get(Context::background(), keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());

        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
    }

    let (_, hash) =
        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
    assert_eq!(format!("{:?}", hash), ALL_ITEMS_ROOT);
}

#[test]
fn test_remove() {
    let mut tree = UrkelTree::make()
        .with_capacity(0, 0)
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    // First insert keys 0..n and remove them in order n..0.
    let mut roots: Vec<Hash> = Vec::new();
    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(
            Context::background(),
            keys[i].as_slice(),
            values[i].as_slice(),
        )
        .expect("insert");

        let value = tree
            .get(Context::background(), keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());

        let (_, hash) = UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0)
            .expect("commit");
        roots.push(hash);
    }

    assert_eq!(format!("{:?}", roots[roots.len() - 1]), ALL_ITEMS_ROOT);

    for i in (1..keys.len()).rev() {
        tree.remove(Context::background(), keys[i].as_slice())
            .expect("remove");

        assert_eq!(
            None,
            tree.get(Context::background(), keys[i].as_slice())
                .expect("get")
        );

        let (_, hash) = UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0)
            .expect("commit");
        assert_eq!(hash, roots[i - 1]);
    }

    tree.remove(Context::background(), keys[0].as_slice())
        .expect("remove");
    let (_, hash) =
        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
    assert_eq!(hash, Hash::empty_hash());

    // Now re-insert keys n..0, remove them in order 0..n.
    for i in (0..keys.len()).rev() {
        tree.insert(
            Context::background(),
            keys[i].as_slice(),
            values[i].as_slice(),
        )
        .expect("insert");

        let value = tree
            .get(Context::background(), keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());

        let (_, _) = UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0)
            .expect("commit");
    }

    for i in 0..keys.len() {
        tree.remove(Context::background(), keys[i].as_slice())
            .expect("remove");

        assert_eq!(
            None,
            tree.get(Context::background(), keys[i].as_slice())
                .expect("get")
        );

        let (_, _) = UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0)
            .expect("commit");
    }

    let (_, hash) =
        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
    assert_eq!(hash, Hash::empty_hash());
}

#[test]
fn test_syncer_basic_no_prefetch() {
    let mut tree = UrkelTree::make()
        .with_capacity(0, 0)
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(
            Context::background(),
            keys[i].as_slice(),
            values[i].as_slice(),
        )
        .expect("insert");
    }

    let (_, hash) =
        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
    assert_eq!(format!("{:?}", hash), ALL_ITEMS_ROOT);

    // Create a "remote" tree that talks to the original tree via the
    // syncer interface. First try with no prefetching and then with
    // prefetching.

    let stats = StatsCollector::new(Box::new(tree));
    let remote_tree = UrkelTree::make()
        .with_capacity(0, 0)
        .with_root(Root {
            hash,
            ..Default::default()
        })
        .new(Context::background(), Box::new(stats))
        .expect("with_root");

    for i in 0..keys.len() {
        let value = remote_tree
            .get(Context::background(), keys[i].as_slice())
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
        assert_eq!(637, stats.path_fetches, "path fetches (no prefetch)");
        assert_eq!(0, stats.value_fetches, "value fetches (no prefetch)");
    }
}

#[test]
fn test_syncer_basic_with_prefetch() {
    let mut tree = UrkelTree::make()
        .with_capacity(0, 0)
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(
            Context::background(),
            keys[i].as_slice(),
            values[i].as_slice(),
        )
        .expect("insert");
    }

    let (_, hash) =
        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
    assert_eq!(format!("{:?}", hash), ALL_ITEMS_ROOT);

    // Create a "remote" tree that talks to the original tree via the
    // syncer interface. First try with no prefetching and then with
    // prefetching.

    let stats = StatsCollector::new(Box::new(tree));
    let remote_tree = UrkelTree::make()
        .with_capacity(0, 0)
        .with_root(Root {
            hash,
            ..Default::default()
        })
        .with_prefetch_depth(12)
        .new(Context::background(), Box::new(stats))
        .expect("with_root");

    for i in 0..keys.len() {
        let value = remote_tree
            .get(Context::background(), keys[i].as_slice())
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
        assert_eq!(224, stats.path_fetches, "path fetches (with prefetch)");
        assert_eq!(0, stats.value_fetches, "value fetches (with prefetch)");
    }
}

#[test]
fn test_syncer_get_path() {
    let mut tree = UrkelTree::make()
        .with_capacity(0, 0)
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(
            Context::background(),
            keys[i].as_slice(),
            values[i].as_slice(),
        )
        .expect("insert");
    }

    let (_, hash) =
        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");

    // Test with a remote tree via the read-syncer interface.
    let mut remote_tree = UrkelTree::make()
        .with_capacity(0, 0)
        .with_root(Root {
            hash,
            ..Default::default()
        })
        .with_prefetch_depth(10)
        .new(Context::background(), Box::new(tree))
        .expect("with_root");

    for i in 0..keys.len() {
        let st = remote_tree
            .get_path(
                Context::background(),
                Root {
                    hash,
                    ..Default::default()
                },
                NodeID::root(),
                &keys[i],
            )
            .expect("get_path");

        // Reconstructed subtree should contain key as leaf node.
        let mut found_leaf = false;
        for n in st.full_nodes {
            match classify_noderef!(?n) {
                NodeKind::Leaf => {
                    let n = n.unwrap();
                    if noderef_as!(n, Leaf).key == keys[i] {
                        assert_eq!(
                            values[i],
                            noderef_as!(n, Leaf)
                                .value
                                .borrow()
                                .value
                                .as_ref()
                                .unwrap()
                                .as_slice()
                        );
                        found_leaf = true;
                        break;
                    }
                }
                _ => {}
            }
        }
        assert_eq!(true, found_leaf, "subtree should contain target leaf");
    }
}

#[test]
fn test_syncer_remove() {
    let mut tree = UrkelTree::make()
        .with_capacity(0, 0)
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");
    let mut roots: Vec<Hash> = Vec::new();

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(
            Context::background(),
            keys[i].as_slice(),
            values[i].as_slice(),
        )
        .expect("insert");

        let (_, hash) = UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0)
            .expect("commit");
        roots.push(hash);
    }

    assert_eq!(format!("{:?}", roots[roots.len() - 1]), ALL_ITEMS_ROOT);

    let mut remote_tree = UrkelTree::make()
        .with_capacity(0, 0)
        .with_root(Root {
            hash: roots[roots.len() - 1],
            ..Default::default()
        })
        .new(Context::background(), Box::new(tree))
        .expect("with_root");

    for i in (0..keys.len()).rev() {
        println!("i={}", i);
        remote_tree
            .remove(Context::background(), keys[i].as_slice())
            .expect("remove");
    }

    let (_, hash) = UrkelTree::commit(
        &mut remote_tree,
        Context::background(),
        Default::default(),
        0,
    )
    .expect("commit");
    assert_eq!(hash, Hash::empty_hash());
}

#[test]
fn test_value_eviction() {
    let mut tree = UrkelTree::make()
        .with_capacity(0, 512)
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(
            Context::background(),
            keys[i].as_slice(),
            values[i].as_slice(),
        )
        .expect("insert");
    }
    UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");

    let stats = tree.stats(Context::background(), 0);
    assert_eq!(
        999, stats.cache.internal_node_count,
        "cache.internal_node_count"
    );
    assert_eq!(1000, stats.cache.leaf_node_count, "cache.leaf_node_count");
    // Only a subset of the leaf values should remain in cache.
    assert_eq!(508, stats.cache.leaf_value_size, "cache.leaf_value_size");
}

#[test]
fn test_node_eviction() {
    let mut tree = UrkelTree::make()
        .with_capacity(128, 0)
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let (keys, values) = generate_key_value_pairs_ex("foo".to_string(), 150);
    for i in 0..keys.len() {
        tree.insert(
            Context::background(),
            keys[i].as_slice(),
            values[i].as_slice(),
        )
        .expect("insert");
    }
    UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");

    let (keys, values) = generate_key_value_pairs_ex("foo key 1".to_string(), 150);
    for i in 0..keys.len() {
        tree.insert(
            Context::background(),
            keys[i].as_slice(),
            values[i].as_slice(),
        )
        .expect("insert");
    }
    UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");

    let stats = tree.stats(Context::background(), 0);
    // Only a subset of nodes should remain in cache.
    assert_eq!(
        67, stats.cache.internal_node_count,
        "cache.internal_node_count"
    );
    assert_eq!(61, stats.cache.leaf_node_count, "cache.leaf_node_count");
    // Only a subset of the leaf values should remain in cache.
    assert_eq!(1032, stats.cache.leaf_value_size, "cache.leaf_value_size");
}

#[test]
fn test_debug_dump() {
    let mut tree = UrkelTree::make()
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");
    tree.insert(Context::background(), b"foo 1", b"bar 1")
        .expect("insert");
    tree.insert(Context::background(), b"foo 2", b"bar 2")
        .expect("insert");
    tree.insert(Context::background(), b"foo 3", b"bar 3")
        .expect("insert");
    tree.insert(Context::background(), b"foo", b"bar")
        .expect("insert");

    let mut output: Vec<u8> = Vec::new();
    tree.dump(Context::background(), &mut output).expect("dump");
    assert!(output.len() > 0);
}

#[test]
fn test_debug_stats() {
    let mut tree = UrkelTree::make()
        .with_capacity(0, 0)
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(
            Context::background(),
            keys[i].as_slice(),
            values[i].as_slice(),
        )
        .expect("insert");
    }

    let stats = tree.stats(Context::background(), 0);
    assert_eq!(14, stats.max_depth, "max_depth");
    assert_eq!(999, stats.internal_node_count, "internal_node_count");
    assert_eq!(901, stats.leaf_node_count, "leaf_node_count");
    assert_eq!(8107, stats.leaf_value_size, "leaf_value_size");
    assert_eq!(99, stats.dead_node_count, "dead_node_count");
    // Cached node counts will update on commit.
    assert_eq!(
        0, stats.cache.internal_node_count,
        "cache.internal_node_count"
    );
    assert_eq!(0, stats.cache.leaf_node_count, "cache.leaf_node_count");
    // Cached leaf value size will update on commit.
    assert_eq!(0, stats.cache.leaf_value_size, "cache.leaf_value_size");

    UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");

    let stats = tree.stats(Context::background(), 0);
    assert_eq!(14, stats.max_depth, "max_depth");
    assert_eq!(999, stats.internal_node_count, "internal_node_count");
    assert_eq!(901, stats.leaf_node_count, "leaf_node_count");
    assert_eq!(8107, stats.leaf_value_size, "leaf_value_size");
    assert_eq!(99, stats.dead_node_count, "dead_node_count");
    assert_eq!(
        999, stats.cache.internal_node_count,
        "cache.internal_node_count"
    );
    assert_eq!(1000, stats.cache.leaf_node_count, "cache.leaf_node_count");
    assert_eq!(8890, stats.cache.leaf_value_size, "cache.leaf_value_size");
}
