use std::{
    cell::RefCell,
    collections::BTreeMap,
    rc::Rc,
    sync::{Arc, Mutex},
};

use failure::Fallible;
use io_context::Context;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{cache::*, sync::*, tree::*},
};

pub struct PendingLogEntry {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
    pub existed: bool,
}

/// A container for the parameters used to construct a new Urkel tree instance.
pub struct UrkelOptions {
    node_capacity: usize,
    value_capacity: usize,
    prefetch_depth: DepthType,
    root_hash: Option<Hash>,
}

impl UrkelOptions {
    /// Set the capacity of the underlying in-memory cache.
    ///
    /// * `node_capacity` is the maximum number of nodes held by the
    ///   cache before eviction.
    /// * `value_capacity` is the total size, in bytes, of values held
    ///   by the cache before eviction.
    ///
    /// If unspecified or 0, the cache will have an unlimited capacity.
    pub fn with_capacity(mut self, node_capacity: usize, value_capacity: usize) -> Self {
        self.node_capacity = node_capacity;
        self.value_capacity = value_capacity;
        self
    }

    /// Set the prefetch depth for subtree prefetching.
    ///
    /// If unspecified or 0, no prefetching will be done.
    pub fn with_prefetch_depth(mut self, prefetch_depth: DepthType) -> Self {
        self.prefetch_depth = prefetch_depth;
        self
    }

    /// Set an existing root hash as the root for the new tree.
    pub fn with_root(mut self, root_hash: Hash) -> Self {
        self.root_hash = Some(root_hash);
        self
    }

    /// Commit the options set so far into a newly constructed tree instance.
    pub fn new(self, ctx: Context, read_syncer: Box<dyn ReadSync>) -> Fallible<UrkelTree> {
        UrkelTree::new(ctx, read_syncer, &self)
    }
}

/// Statistics about an Urkel tree instance.
#[derive(Debug, Default)]
pub struct UrkelStats {
    /// The maximum depth of the tree.
    pub max_depth: DepthType,
    /// The counf of internal nodes in the tree structure.
    pub internal_node_count: u64,
    /// The count of leaf nodes in the tree structure.
    pub leaf_node_count: u64,
    /// The total size of values stored in the tree.
    pub leaf_value_size: usize,
    /// The count of dangling pointers.
    pub dead_node_count: u64,

    /// Maximum subtree depths at each level for left pointers.
    pub left_subtree_max_depths: BTreeMap<DepthType, DepthType>,
    /// Maximum subtree depths at each level for right pointers.
    pub right_subtree_max_depths: BTreeMap<DepthType, DepthType>,

    /// Statistics about the in-memory cache.
    pub cache: CacheStats,
}

/// An Urkel tree-based MKVS implementation.
pub struct UrkelTree {
    pub cache: RefCell<Box<LRUCache>>,
    pub pending_write_log: BTreeMap<Key, PendingLogEntry>,
    pub lock: Arc<Mutex<isize>>,
}

impl UrkelTree {
    /// Construct a new tree instance using the given read syncer and options struct.
    pub fn new(
        ctx: Context,
        read_syncer: Box<dyn ReadSync>,
        opts: &UrkelOptions,
    ) -> Fallible<UrkelTree> {
        let ctx = ctx.freeze();
        let tree = UrkelTree {
            cache: RefCell::new(LRUCache::new(
                opts.node_capacity,
                opts.value_capacity,
                read_syncer,
            )),
            pending_write_log: BTreeMap::new(),
            lock: Arc::new(Mutex::new(0)),
        };

        tree.cache
            .borrow_mut()
            .set_prefetch_depth(opts.prefetch_depth);

        if let Some(root_hash) = opts.root_hash {
            tree.cache
                .borrow_mut()
                .set_pending_root(Rc::new(RefCell::new(NodePointer {
                    clean: true,
                    hash: root_hash,
                    ..Default::default()
                })));
            tree.cache.borrow_mut().set_sync_root(root_hash);
            // NOTE: Path can be anything here as the depth is 0 so it is actually ignored.
            let ptr = tree
                .cache
                .borrow_mut()
                .prefetch(&ctx, root_hash, Key::new(), 0)?;
            if !ptr.borrow().is_null() {
                tree.cache.borrow_mut().set_pending_root(ptr);
            }
        }

        Ok(tree)
    }

    /// Return an options struct to chain configuration calls on.
    pub fn make() -> UrkelOptions {
        UrkelOptions {
            node_capacity: 0,
            value_capacity: 0,
            prefetch_depth: 0,
            root_hash: None,
        }
    }
}
