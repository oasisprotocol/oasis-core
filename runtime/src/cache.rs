//! In-memory cache of trees.
use std::{
    cell::RefCell,
    num::NonZeroUsize,
    rc::Rc,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{
    common::crypto::hash::Hash,
    protocol::Protocol,
    storage::mkvs::{sync::HostReadSyncer, Root, Tree},
    types::HostStorageEndpoint,
};

thread_local! {
    static QUERY_CACHE: RefCell<lru::LruCache<u64, Rc<RefCell<Cache>>>> = RefCell::new(lru::LruCache::new(NonZeroUsize::new(10).unwrap()));
}

/// A set of storage tree caches, one for each storage operation:
///
/// * **Execution** and **checking** of transactions each have their own cache guarded by a mutex
///   since the usual use case is that only one execution/check batch is running at any given time.
///
/// * **Queries** have a thread-local cache as there can be multiple queries running at any given
///   time and having a global lock would kill concurrency.
#[derive(Clone)]
pub struct CacheSet {
    protocol: Arc<Protocol>,
    execute: Arc<Mutex<Cache>>,
    check: Arc<Mutex<Cache>>,
}

impl CacheSet {
    /// Create a new empty cache set.
    pub fn new(protocol: Arc<Protocol>) -> Self {
        Self {
            execute: Arc::new(Mutex::new(Cache::new(&protocol))),
            check: Arc::new(Mutex::new(Cache::new(&protocol))),
            protocol,
        }
    }

    /// Cache used for executing transactions.
    pub fn execute(&self, root: Root) -> MutexGuard<'_, Cache> {
        let mut cache = self.execute.lock().unwrap();
        cache.maybe_replace(&self.protocol, root);
        cache
    }

    /// Cache used for checking transactions.
    pub fn check(&self, root: Root) -> MutexGuard<'_, Cache> {
        let mut cache = self.check.lock().unwrap();
        cache.maybe_replace(&self.protocol, root);
        cache
    }

    /// Cache used for queries.
    pub fn query(&self, root: Root) -> Rc<RefCell<Cache>> {
        let cache = QUERY_CACHE.with(|caches| {
            let mut caches = caches.borrow_mut();
            if let Some(cache) = caches.get(&root.version) {
                return cache.clone();
            }

            let cache = Rc::new(RefCell::new(Cache::new(&self.protocol)));
            caches.put(root.version, cache.clone());
            cache
        });
        cache.borrow_mut().maybe_replace(&self.protocol, root);
        cache
    }
}

/// Cached storage tree with an associated root.
pub struct Cache {
    root: Root,
    tree: Tree,
}

impl Cache {
    fn new(protocol: &Arc<Protocol>) -> Self {
        Self {
            root: Default::default(),
            tree: Self::build(protocol, Default::default()),
        }
    }

    fn build(protocol: &Arc<Protocol>, root: Root) -> Tree {
        let config = protocol.get_config();
        let read_syncer = HostReadSyncer::new(protocol.clone(), HostStorageEndpoint::Runtime);
        Tree::builder()
            .with_capacity(
                config.storage.cache_node_capacity,
                config.storage.cache_value_capacity,
            )
            .with_root(root)
            .build(Box::new(read_syncer))
    }

    fn maybe_replace(&mut self, protocol: &Arc<Protocol>, root: Root) {
        if self.root == root {
            return;
        }

        self.tree = Self::build(protocol, root);
        self.root = root;
    }

    /// Reference to the cached tree.
    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    /// Mutable reference to the cached tree.
    pub fn tree_mut(&mut self) -> &mut Tree {
        &mut self.tree
    }

    /// Commits a specific version and root as being stored by the tree.
    pub fn commit(&mut self, version: u64, hash: Hash) {
        self.root.version = version;
        self.root.hash = hash;
    }
}
