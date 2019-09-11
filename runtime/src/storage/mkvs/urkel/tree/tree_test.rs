use io_context::Context;
use std::{collections::HashSet, iter::FromIterator};

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::{
        urkel::{
            cache::*,
            interop::{Driver, ProtocolServer},
            sync::*,
            tree::*,
        },
        LogEntry, LogEntryKind, WriteLog,
    },
};

const INSERT_ITEMS: usize = 1000;
const ALL_ITEMS_ROOT: &str = "a092507adb90fce8d38e8c8663f4db0affa50e47955535bbdb21327a8d9c2532";

const LONG_KEY: &str = "Unlock the potential of your data without compromising security or privacy";
const LONG_VALUE: &str = "The platform that puts data privacy first. From sharing medical records, to analyzing personal financial information, to training machine learning models, the Oasis platform supports applications that use even the most sensitive data without compromising privacy or performance.";
const ALL_LONG_ITEMS_ROOT: &str =
    "1aa1b04b41ea1cbf3f5ff839bfb1c21cacddc06b773b94b425d46b673352459b";

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
        "ebf4bddfa659ceed844b04d62e05c2b8cb5ef1f6d73c6026f63d289b6777ce44"
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
        "5c71b5ed7fe2ea8fd663254fd54d648db8e8f285c5712e943321ca7a6710d8ca"
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
        "ebf4bddfa659ceed844b04d62e05c2b8cb5ef1f6d73c6026f63d289b6777ce44"
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
fn test_syncer_basic() {
    let server = ProtocolServer::new();

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

    let (write_log, hash) =
        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
    assert_eq!(format!("{:?}", hash), ALL_ITEMS_ROOT);

    server.apply(&write_log, hash, Default::default(), 0);

    // Create a "remote" tree that talks to the original tree via the
    // syncer interface.

    let stats = StatsCollector::new(server.read_sync());
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

    let cache = remote_tree.cache.borrow();
    let stats = cache
        .get_read_syncer()
        .as_any()
        .downcast_ref::<StatsCollector>()
        .expect("stats");
    assert_eq!(keys.len(), stats.sync_get_count, "sync_get count");
    assert_eq!(0, stats.sync_get_prefixes_count, "sync_get_prefixes count");
    assert_eq!(0, stats.sync_iterate_count, "sync_iterate count");
}

#[test]
fn test_syncer_remove() {
    let server = ProtocolServer::new();

    let mut tree = UrkelTree::make()
        .with_capacity(0, 0)
        .new(Context::background(), Box::new(NoopReadSyncer {}))
        .expect("new_tree");
    let mut roots: Vec<Hash> = Vec::new();

    let mut write_log = WriteLog::new();
    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(
            Context::background(),
            keys[i].as_slice(),
            values[i].as_slice(),
        )
        .expect("insert");

        let (mut wl, hash) =
            UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0)
                .expect("commit");
        roots.push(hash);
        write_log.append(&mut wl);
    }

    assert_eq!(format!("{:?}", roots[roots.len() - 1]), ALL_ITEMS_ROOT);
    server.apply(&write_log, roots[roots.len() - 1], Default::default(), 0);

    let stats = StatsCollector::new(server.read_sync());
    let mut remote_tree = UrkelTree::make()
        .with_capacity(0, 0)
        .with_root(Root {
            hash: roots[roots.len() - 1],
            ..Default::default()
        })
        .new(Context::background(), Box::new(stats))
        .expect("with_root");

    for i in (0..keys.len()).rev() {
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

    let cache = remote_tree.cache.borrow();
    let stats = cache
        .get_read_syncer()
        .as_any()
        .downcast_ref::<StatsCollector>()
        .expect("stats");
    assert_eq!(850, stats.sync_get_count, "sync_get count");
    assert_eq!(0, stats.sync_get_prefixes_count, "sync_get_prefixes count");
    assert_eq!(0, stats.sync_iterate_count, "sync_iterate count");
}

#[test]
fn test_syncer_insert() {
    let server = ProtocolServer::new();

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

    let (write_log, hash) =
        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
    server.apply(&write_log, hash, Default::default(), 0);

    let stats = StatsCollector::new(server.read_sync());
    let mut remote_tree = UrkelTree::make()
        .with_capacity(0, 0)
        .with_root(Root {
            hash,
            ..Default::default()
        })
        .new(Context::background(), Box::new(stats))
        .expect("with_root");

    for i in 0..keys.len() {
        remote_tree
            .insert(
                Context::background(),
                keys[i].as_slice(),
                values[i].as_slice(),
            )
            .expect("insert");
    }

    let cache = remote_tree.cache.borrow();
    let stats = cache
        .get_read_syncer()
        .as_any()
        .downcast_ref::<StatsCollector>()
        .expect("stats");
    assert_eq!(1000, stats.sync_get_count, "sync_get count");
    assert_eq!(0, stats.sync_get_prefixes_count, "sync_get_prefixes count");
    assert_eq!(0, stats.sync_iterate_count, "sync_iterate count");
}

#[test]
fn test_syncer_prefetch_prefixes() {
    let server = ProtocolServer::new();

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

    let (write_log, hash) =
        UrkelTree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
    server.apply(&write_log, hash, Default::default(), 0);

    let stats = StatsCollector::new(server.read_sync());
    let remote_tree = UrkelTree::make()
        .with_capacity(0, 0)
        .with_root(Root {
            hash,
            ..Default::default()
        })
        .new(Context::background(), Box::new(stats))
        .expect("with_root");

    // Prefetch keys starting with prefix "key".
    remote_tree
        .prefetch_prefixes(Context::background(), &vec![b"key".to_vec().into()], 1000)
        .expect("prefetch_prefixes");

    for i in 0..keys.len() {
        let value = remote_tree
            .get(Context::background(), keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());
    }

    let cache = remote_tree.cache.borrow();
    let stats = cache
        .get_read_syncer()
        .as_any()
        .downcast_ref::<StatsCollector>()
        .expect("stats");
    assert_eq!(0, stats.sync_get_count, "sync_get count");
    assert_eq!(1, stats.sync_get_prefixes_count, "sync_get_prefixes count");
    assert_eq!(0, stats.sync_iterate_count, "sync_iterate count");
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

    assert_eq!(
        999,
        tree.cache.borrow().stats().internal_node_count,
        "cache.internal_node_count"
    );
    assert_eq!(
        1000,
        tree.cache.borrow().stats().leaf_node_count,
        "cache.leaf_node_count"
    );
    // Only a subset of the leaf values should remain in cache.
    assert_eq!(
        508,
        tree.cache.borrow().stats().leaf_value_size,
        "cache.leaf_value_size"
    );
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

    // Only a subset of nodes should remain in cache.
    assert_eq!(
        67,
        tree.cache.borrow().stats().internal_node_count,
        "cache.internal_node_count"
    );
    assert_eq!(
        61,
        tree.cache.borrow().stats().leaf_node_count,
        "cache.leaf_node_count"
    );
    // Only a subset of the leaf values should remain in cache.
    assert_eq!(
        1032,
        tree.cache.borrow().stats().leaf_value_size,
        "cache.leaf_value_size"
    );
}
