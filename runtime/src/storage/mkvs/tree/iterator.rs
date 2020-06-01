//! Tree iterator.
use std::{collections::VecDeque, fmt, iter::Iterator, mem::replace, sync::Arc};

use failure::{Error, Fallible};
use io_context::Context;

use crate::storage::mkvs::{cache::*, sync::*, tree::*};

pub(super) struct FetcherSyncIterate<'a> {
    key: &'a Key,
    prefetch: usize,
}

impl<'a> FetcherSyncIterate<'a> {
    pub(super) fn new(key: &'a Key, prefetch: usize) -> Self {
        Self { key, prefetch }
    }
}

impl<'a> ReadSyncFetcher for FetcherSyncIterate<'a> {
    fn fetch(
        &self,
        ctx: Context,
        root: Root,
        ptr: NodePtrRef,
        rs: &mut Box<dyn ReadSync>,
    ) -> Fallible<Proof> {
        let rsp = rs.sync_iterate(
            ctx,
            IterateRequest {
                tree: TreeID {
                    root,
                    position: ptr.borrow().hash,
                },
                key: self.key.clone(),
                prefetch: self.prefetch as u16,
            },
        )?;
        Ok(rsp.proof)
    }
}

/// Visit state of a node.
#[derive(Debug, PartialEq)]
enum VisitState {
    Before,
    At,
    AtLeft,
    After,
}

/// Atom in the current iterator path. Can be used to resume iteration
/// from a given position.
struct PathAtom {
    ptr: NodePtrRef,
    bit_depth: Depth,
    path: Key,
    state: VisitState,
}

impl fmt::Debug for PathAtom {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("PathAtom")
            .field("bit_depth", &self.bit_depth)
            .field("path", &self.path)
            .field("state", &self.state)
            .finish()
    }
}

/// Tree iterator.
pub struct TreeIterator<'tree> {
    ctx: Arc<Context>,
    tree: &'tree Tree,
    prefetch: usize,
    pos: VecDeque<PathAtom>,
    key: Option<Key>,
    value: Option<Vec<u8>>,
    error: Option<Error>,
}

impl<'tree> TreeIterator<'tree> {
    /// Create a new tree iterator.
    fn new(ctx: Context, tree: &'tree Tree) -> Self {
        Self {
            ctx: ctx.freeze(),
            tree,
            prefetch: 0,
            pos: VecDeque::new(),
            key: None,
            value: None,
            error: None,
        }
    }

    /// Sets the number of next elements to prefetch.
    pub fn set_prefetch(&mut self, prefetch: usize) {
        self.prefetch = prefetch;
    }

    fn reset(&mut self) {
        self.pos.clear();
        self.key = None;
        self.value = None;
    }

    /// Return whether the iterator is valid.
    pub fn is_valid(&self) -> bool {
        self.key.is_some()
    }

    /// Return the error that occurred during iteration if any.
    pub fn error(&self) -> &Option<Error> {
        &self.error
    }

    /// Move the iterator to the first key in the tree.
    pub fn rewind(&mut self) {
        self.seek(&[])
    }

    /// Moves the iterator either at the given key or at the next larger
    /// key.
    pub fn seek(&mut self, key: &[u8]) {
        if self.error.is_some() {
            return;
        }

        self.reset();
        let pending_root = self.tree.cache.borrow().get_pending_root();
        if let Err(error) = self._next(
            pending_root,
            0,
            Key::new(),
            key.to_vec(),
            VisitState::Before,
        ) {
            self.error = Some(error);
            self.reset();
        }
    }

    fn next(&mut self) {
        if self.error.is_some() {
            return;
        }

        while !self.pos.is_empty() {
            // Start where we left off.
            let atom = self.pos.pop_front().expect("not empty");
            let mut remainder = replace(&mut self.pos, VecDeque::new());

            // Remember where the path from root to target node ends (will end).
            let mut cache = self.tree.cache.borrow_mut();
            cache.mark_position();
            for atom in &remainder {
                cache.use_node(atom.ptr.clone());
            }
            drop(cache);

            // Try to proceed with the current node. If we don't succeed, proceed to the
            // next node.
            let key = self.key.take().expect("iterator is valid");
            self.reset();
            if let Err(error) =
                self._next(atom.ptr, atom.bit_depth, atom.path, key.clone(), atom.state)
            {
                self.error = Some(error);
                self.reset();
                return;
            }
            if self.key.is_some() {
                // Key has been found.
                self.pos.append(&mut remainder);
                return;
            }

            self.key = Some(key);
            self.pos = remainder;
        }

        // We have reached the end of the tree, make sure everything is reset.
        self.key = None;
        self.value = None;
    }

    fn _next(
        &mut self,
        ptr: NodePtrRef,
        bit_depth: Depth,
        path: Key,
        mut key: Key,
        mut state: VisitState,
    ) -> Fallible<()> {
        let node_ref = self.tree.cache.borrow_mut().deref_node_ptr(
            &self.ctx,
            ptr.clone(),
            Some(FetcherSyncIterate::new(&key, self.prefetch)),
        )?;

        match classify_noderef!(?node_ref) {
            NodeKind::None => {
                // Reached a nil node, there is nothing here.
                Ok(())
            }
            NodeKind::Internal => {
                let node_ref = node_ref.unwrap();
                if let NodeBox::Internal(ref n) = *node_ref.borrow() {
                    // Internal node.
                    let bit_length = bit_depth + n.label_bit_length;
                    let new_path = path.merge(bit_depth, &n.label, n.label_bit_length);

                    // Check if the key is longer than the current path but lexicographically smaller. In this
                    // case everything in this subtree will be larger so we need to take the first value.
                    // takeFirst bool
                    let take_first =
                        if bit_length > 0 && key.bit_length() >= bit_length && key < new_path {
                            true
                        } else {
                            false
                        };

                    // Does lookup key end here? Look into LeafNode.
                    if (state == VisitState::Before
                        && (key.bit_length() <= bit_length || take_first))
                        || state == VisitState::At
                    {
                        if state == VisitState::Before {
                            self._next(
                                n.leaf_node.clone(),
                                bit_length,
                                path.clone(),
                                key.clone(),
                                VisitState::Before,
                            )?;
                            if self.key.is_some() {
                                // Key has been found.
                                self.pos.push_back(PathAtom {
                                    ptr,
                                    bit_depth,
                                    path,
                                    state: VisitState::At,
                                });
                                return Ok(());
                            }
                        }
                        // Key has not been found, continue with search for next key.
                        if key.bit_length() <= bit_length {
                            key = key.append_bit(bit_length, false);
                        }
                    }

                    if state == VisitState::Before {
                        state = VisitState::At;
                    }

                    // Continue recursively based on a bit value.
                    if (state == VisitState::At && (!key.get_bit(bit_length) || take_first))
                        || state == VisitState::AtLeft
                    {
                        if state == VisitState::At {
                            self._next(
                                n.left.clone(),
                                bit_length,
                                new_path.append_bit(bit_length, false),
                                key.clone(),
                                VisitState::Before,
                            )?;
                            if self.key.is_some() {
                                // Key has been found.
                                self.pos.push_back(PathAtom {
                                    ptr,
                                    bit_depth,
                                    path,
                                    state: VisitState::AtLeft,
                                });
                                return Ok(());
                            }
                        }
                        // Key has not been found, continue with search for next key.
                        key = key.split(bit_length, key.bit_length()).0;
                        key = key.append_bit(bit_length, true);
                    }

                    if state == VisitState::At || state == VisitState::AtLeft {
                        self._next(
                            n.right.clone(),
                            bit_length,
                            new_path.append_bit(bit_length, true),
                            key,
                            VisitState::Before,
                        )?;
                        if self.key.is_some() {
                            // Key has been found.
                            self.pos.push_back(PathAtom {
                                ptr,
                                bit_depth,
                                path,
                                state: VisitState::After,
                            });
                            return Ok(());
                        }
                    }

                    return Ok(());
                }

                unreachable!("node kind is internal node");
            }
            NodeKind::Leaf => {
                // Reached a leaf node.
                let node_ref = node_ref.unwrap();
                if let NodeBox::Leaf(ref n) = *node_ref.borrow() {
                    if n.key >= key {
                        self.key = Some(n.key.clone());
                        self.value = Some(n.value.clone());
                    }
                } else {
                    unreachable!("node kind is leaf node");
                }

                Ok(())
            }
        }
    }
}

impl<'tree> Iterator for TreeIterator<'tree> {
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        if !self.is_valid() {
            return None;
        }

        let key = self.key.as_ref().expect("iterator is valid").clone();
        let value = self.value.as_ref().expect("iterator is valid").clone();
        self.next();

        Some((key, value))
    }
}

impl Tree {
    /// Returns an iterator over the tree.
    pub fn iter(&self, ctx: Context) -> TreeIterator {
        TreeIterator::new(ctx, self)
    }
}

#[cfg(test)]
mod test {
    use io_context::Context;
    use rustc_hex::FromHex;

    use super::{tree_test::generate_key_value_pairs_ex, *};
    use crate::storage::mkvs::interop::{Driver, ProtocolServer};

    #[test]
    fn test_iterator() {
        let server = ProtocolServer::new();

        let mut tree = Tree::make().new(Box::new(NoopReadSyncer {}));

        // Test with an empty tree.
        let mut it = tree.iter(Context::background());
        it.rewind();
        assert!(
            !it.is_valid(),
            "iterator should be invalid on an empty tree"
        );

        // Test with one item.
        tree.insert(Context::background(), b"key", b"first")
            .unwrap();
        let mut it = tree.iter(Context::background());
        it.rewind();
        assert!(
            it.is_valid(),
            "iterator should be valid on a non-empty tree"
        );

        // Insert some items.
        let items = vec![
            (b"key".to_vec(), b"first".to_vec()),
            (b"key 1".to_vec(), b"one".to_vec()),
            (b"key 2".to_vec(), b"two".to_vec()),
            (b"key 5".to_vec(), b"five".to_vec()),
            (b"key 8".to_vec(), b"eight".to_vec()),
            (b"key 9".to_vec(), b"nine".to_vec()),
        ];
        for (key, value) in items.iter() {
            tree.insert(Context::background(), key, value).unwrap();
        }

        let tests = vec![
            (b"k".to_vec(), 0),
            (b"key 1".to_vec(), 1),
            (b"key 3".to_vec(), 3),
            (b"key 4".to_vec(), 3),
            (b"key 5".to_vec(), 3),
            (b"key 6".to_vec(), 4),
            (b"key 7".to_vec(), 4),
            (b"key 8".to_vec(), 4),
            (b"key 9".to_vec(), 5),
            (b"key A".to_vec(), -1),
        ];

        // Direct.
        let it = tree.iter(Context::background());
        test_iterator_with(&items, it, &tests);

        // Remote.
        let (write_log, hash) =
            Tree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
        server.apply(&write_log, hash, Default::default(), 0);

        let remote_tree = Tree::make()
            .with_capacity(0, 0)
            .with_root(Root {
                hash,
                ..Default::default()
            })
            .new(server.read_sync());

        let it = remote_tree.iter(Context::background());
        test_iterator_with(&items, it, &tests);

        // Remote with prefetch (10).
        let stats = StatsCollector::new(server.read_sync());
        let remote_tree = Tree::make()
            .with_capacity(0, 0)
            .with_root(Root {
                hash,
                ..Default::default()
            })
            .new(Box::new(stats));

        let mut it = remote_tree.iter(Context::background());
        it.set_prefetch(10);
        test_iterator_with(&items, it, &tests);

        let cache = remote_tree.cache.borrow();
        let stats = cache
            .get_read_syncer()
            .as_any()
            .downcast_ref::<StatsCollector>()
            .expect("stats");
        assert_eq!(0, stats.sync_get_count, "sync_get_count");
        assert_eq!(0, stats.sync_get_prefixes_count, "sync_get_prefixes_count");
        assert_eq!(1, stats.sync_iterate_count, "sync_iterate_count");

        // Remote with prefetch (3).
        let stats = StatsCollector::new(server.read_sync());
        let remote_tree = Tree::make()
            .with_capacity(0, 0)
            .with_root(Root {
                hash,
                ..Default::default()
            })
            .new(Box::new(stats));

        let mut it = remote_tree.iter(Context::background());
        it.set_prefetch(3);
        test_iterator_with(&items, it, &tests);

        let cache = remote_tree.cache.borrow();
        let stats = cache
            .get_read_syncer()
            .as_any()
            .downcast_ref::<StatsCollector>()
            .expect("stats");
        assert_eq!(0, stats.sync_get_count, "sync_get_count");
        assert_eq!(0, stats.sync_get_prefixes_count, "sync_get_prefixes_count");
        assert_eq!(2, stats.sync_iterate_count, "sync_iterate_count");
    }

    #[test]
    fn test_iterator_case1() {
        let mut tree = Tree::make().new(Box::new(NoopReadSyncer {}));

        let items = vec![
            (b"key 5".to_vec(), b"fivey".to_vec()),
            (b"key 7".to_vec(), b"seven".to_vec()),
        ];
        for (key, value) in items.iter() {
            tree.insert(Context::background(), key, value).unwrap();
        }

        let tests = vec![(b"key 3".to_vec(), 0)];

        let it = tree.iter(Context::background());
        test_iterator_with(&items, it, &tests);
    }

    #[test]
    fn test_iterator_case2() {
        let mut tree = Tree::make().new(Box::new(NoopReadSyncer {}));

        let items: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (
                "54dcb497eb46bc7cb1a1a29d143d5d41f1a684c97e12f2ae536eceb828c15fc34c02"
                    .from_hex()
                    .unwrap(),
                b"value".to_vec(),
            ),
            (
                "54dcb497eb46bc7cb1a1a29d143d5d41f1a684c97e12f2ae536eceb828c15fc34c02"
                    .from_hex()
                    .unwrap(),
                b"value".to_vec(),
            ),
        ];
        for (key, value) in items.iter() {
            tree.insert(Context::background(), key, value).unwrap();
        }

        let mut it = tree.iter(Context::background());
        let missing_key: Vec<u8> =
            "54da85be3251772db943cba67341d402117c87ada2a9e8aad7171d40b6b4dc9fbc"
                .from_hex()
                .unwrap();
        it.seek(&missing_key);
        assert!(it.is_valid(), "iterator should be valid");
        let item = Iterator::next(&mut it);
        assert_eq!(
            Some((items[0].0.clone(), b"value".to_vec())),
            item,
            "value should be correct"
        );
    }

    #[test]
    fn test_iterator_eviction() {
        let server = ProtocolServer::new();

        let mut tree = Tree::make()
            .with_capacity(0, 0)
            .new(Box::new(NoopReadSyncer {}));

        let (keys, values) = generate_key_value_pairs_ex("T".to_owned(), 100);
        let items: Vec<(Vec<u8>, Vec<u8>)> = keys.into_iter().zip(values.into_iter()).collect();
        for (key, value) in &items {
            tree.insert(Context::background(), &key, &value).unwrap();
        }

        let (write_log, hash) =
            Tree::commit(&mut tree, Context::background(), Default::default(), 0).expect("commit");
        server.apply(&write_log, hash, Default::default(), 0);

        // Create a remote tree with limited cache capacity so that nodes will
        // be evicted while iterating.
        let stats = StatsCollector::new(server.read_sync());
        let remote_tree = Tree::make()
            .with_capacity(50, 16 * 1024 * 1024)
            .with_root(Root {
                hash,
                ..Default::default()
            })
            .new(Box::new(stats));

        let mut it = remote_tree.iter(Context::background());
        it.set_prefetch(1000);
        test_iterator_with(&items, it, &vec![]);

        let cache = remote_tree.cache.borrow();
        let stats = cache
            .get_read_syncer()
            .as_any()
            .downcast_ref::<StatsCollector>()
            .expect("stats");
        assert_eq!(0, stats.sync_get_count, "sync_get_count");
        assert_eq!(0, stats.sync_get_prefixes_count, "sync_get_prefixes_count");
        // We require multiple fetches as we can only store a limited amount of
        // results per fetch due to the cache being too small.
        assert_eq!(2, stats.sync_iterate_count, "sync_iterate_count");
    }

    fn test_iterator_with(
        items: &Vec<(Vec<u8>, Vec<u8>)>,
        mut it: TreeIterator,
        tests: &Vec<(Vec<u8>, isize)>,
    ) {
        // Iterate through the whole tree.
        let mut iterations = 0;
        it.rewind();
        for (idx, (key, value)) in it.by_ref().enumerate() {
            if !tests.is_empty() {
                assert_eq!(items[idx].0, key, "iterator should have the correct key");
                assert_eq!(
                    items[idx].1, value,
                    "iterator should have the correct value"
                );
            }
            iterations += 1;
        }
        assert!(it.error().is_none(), "iterator should not error");
        assert_eq!(iterations, items.len(), "iterator should go over all items");

        for (seek, pos) in tests {
            it.seek(&seek);
            if *pos == -1 {
                assert!(!it.is_valid(), "iterator should not be valid after seek");
                continue;
            }

            for expected in &items[*pos as usize..] {
                let item = Iterator::next(&mut it);
                assert_eq!(
                    Some(expected.clone()),
                    item,
                    "iterator should have the correct item"
                );
            }
        }
    }
}
