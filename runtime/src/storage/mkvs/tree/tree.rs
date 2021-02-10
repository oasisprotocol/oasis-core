use std::{cell::RefCell, fmt, rc::Rc};

use anyhow::Result;
use io_context::Context;

use crate::{
    common::{crypto::hash::Hash, namespace::Namespace},
    storage::mkvs::{self, cache::*, sync::*, tree::*},
};

/// A container for the parameters used to construct a new MKVS tree instance.
pub struct Options {
    node_capacity: usize,
    value_capacity: usize,
    root: Option<Root>,
    root_type: Option<RootType>,
}

impl Options {
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
    ///
    /// Either this or a root type must be specified to construct a new
    /// tree. If neither is specified, or if both are set but don't agree on
    /// the root type, the constructor will panic.
    pub fn with_root(mut self, root: Root) -> Self {
        self.root = Some(root);
        self
    }

    /// Set the storage root type for this tree.
    ///
    /// Either this or an existing root must be specified to construct a new
    /// tree. If neither is specified, or if both are set but don't agree on
    /// the root type, the constructor will panic.
    pub fn with_root_type(mut self, root_type: RootType) -> Self {
        self.root_type = Some(root_type);
        self
    }

    /// Commit the options set so far into a newly constructed tree instance.
    pub fn new(self, read_syncer: Box<dyn ReadSync>) -> Tree {
        if self.root_type.is_none() && self.root.is_none() {
            panic!("mkvs/tree: neither root type nor storage root specified");
        }
        if let Some(root) = self.root {
            if let Some(root_type) = self.root_type {
                if root.root_type != root_type {
                    panic!("mkvs/tree: specified storage root and incompatible root type");
                }
            }
        }
        Tree::new(read_syncer, &self)
    }
}

/// A patricia tree-based MKVS implementation.
pub struct Tree {
    pub(crate) cache: RefCell<Box<LRUCache>>,
    pub(crate) root_type: RootType,
}

// Tree is Send as long as ownership of internal Rcs cannot leak out via any of its methods.
unsafe impl Send for Tree {}

impl Tree {
    /// Construct a new tree instance using the given read syncer and options struct.
    pub fn new(read_syncer: Box<dyn ReadSync>, opts: &Options) -> Tree {
        let root_type = if opts.root.is_none() {
            opts.root_type.unwrap()
        } else {
            opts.root.unwrap().root_type
        };
        let tree = Tree {
            cache: RefCell::new(LRUCache::new(
                opts.node_capacity,
                opts.value_capacity,
                read_syncer,
                root_type,
            )),
            root_type: root_type,
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

        tree
    }

    /// Return an options struct to chain configuration calls on.
    pub fn make() -> Options {
        Options {
            node_capacity: 50_000,
            value_capacity: 16 * 1024 * 1024,
            root: None,
            root_type: None,
        }
    }
}

impl fmt::Debug for Tree {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.cache.borrow().get_pending_root().fmt(f)
    }
}

impl mkvs::FallibleMKVS for Tree {
    fn get(&self, ctx: Context, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Tree::get(self, ctx, key)
    }

    fn cache_contains_key(&self, ctx: Context, key: &[u8]) -> bool {
        Tree::cache_contains_key(self, ctx, key)
    }

    fn insert(&mut self, ctx: Context, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        Tree::insert(self, ctx, key, value)
    }

    fn remove(&mut self, ctx: Context, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Tree::remove(self, ctx, key)
    }

    fn prefetch_prefixes(
        &self,
        ctx: Context,
        prefixes: &Vec<mkvs::Prefix>,
        limit: u16,
    ) -> Result<()> {
        Tree::prefetch_prefixes(self, ctx, prefixes, limit)
    }

    fn iter(&self, ctx: Context) -> Box<dyn mkvs::Iterator + '_> {
        Box::new(Tree::iter(self, ctx))
    }

    fn commit(&mut self, ctx: Context, namespace: Namespace, version: u64) -> Result<Hash> {
        Tree::commit(self, ctx, namespace, version)
    }
}
