use std::{
    cell::RefCell,
    collections::BTreeMap,
    fmt,
    rc::Rc,
    sync::{Arc, Mutex},
};

use failure::Fallible;
use io_context::Context;

use crate::storage::mkvs::urkel::{cache::*, sync::*, tree::*};

pub struct PendingLogEntry {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
    pub existed: bool,
}

/// A container for the parameters used to construct a new Urkel tree instance.
pub struct UrkelOptions {
    node_capacity: usize,
    value_capacity: usize,
    root: Option<Root>,
}

impl UrkelOptions {
    /// Set the capacity of the underlying in-memory cache.
    ///
    /// * `node_capacity` is the maximum number of nodes held by the
    ///   cache before eviction.
    /// * `value_capacity` is the total size, in bytes, of values held
    ///   by the cache before eviction.
    ///
    /// If set to 0, the relevant cache will have an unlimited capacity. If left
    /// unspecified, the cache will default to 50_000 for nodes and 16MB for values.
    pub fn with_capacity(mut self, node_capacity: usize, value_capacity: usize) -> Self {
        self.node_capacity = node_capacity;
        self.value_capacity = value_capacity;
        self
    }

    /// Set an existing root as the root for the new tree.
    pub fn with_root(mut self, root: Root) -> Self {
        self.root = Some(root);
        self
    }

    /// Commit the options set so far into a newly constructed tree instance.
    pub fn new(self, ctx: Context, read_syncer: Box<dyn ReadSync>) -> Fallible<UrkelTree> {
        UrkelTree::new(ctx, read_syncer, &self)
    }
}

/// An Urkel tree-based MKVS implementation.
pub struct UrkelTree {
    pub(crate) cache: RefCell<Box<LRUCache>>,
    pub(crate) pending_write_log: BTreeMap<Key, PendingLogEntry>,
    pub(crate) lock: Arc<Mutex<isize>>,
}

impl UrkelTree {
    /// Construct a new tree instance using the given read syncer and options struct.
    pub fn new(
        _ctx: Context,
        read_syncer: Box<dyn ReadSync>,
        opts: &UrkelOptions,
    ) -> Fallible<UrkelTree> {
        let tree = UrkelTree {
            cache: RefCell::new(LRUCache::new(
                opts.node_capacity,
                opts.value_capacity,
                read_syncer,
            )),
            pending_write_log: BTreeMap::new(),
            lock: Arc::new(Mutex::new(0)),
        };

        if let Some(root) = opts.root {
            tree.cache
                .borrow_mut()
                .set_pending_root(Rc::new(RefCell::new(NodePointer {
                    clean: true,
                    hash: root.hash,
                    ..Default::default()
                })));
            tree.cache.borrow_mut().set_sync_root(root);
        }

        Ok(tree)
    }

    /// Return an options struct to chain configuration calls on.
    pub fn make() -> UrkelOptions {
        UrkelOptions {
            node_capacity: 50_000,
            value_capacity: 16 * 1024 * 1024,
            root: None,
        }
    }
}

impl fmt::Debug for UrkelTree {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.cache.borrow().get_pending_root().fmt(f)
    }
}
