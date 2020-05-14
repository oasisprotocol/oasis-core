use std::{any::Any, ptr::NonNull, sync::Arc};

use failure::Fallible;
use io_context::Context;

use crate::storage::mkvs::{cache::lru_cache::CacheItemBox, sync::*, tree::*};

/// Statistics about the contents of the cache.
#[derive(Debug, Default)]
pub struct CacheStats {
    /// Count of internal nodes held by the cache.
    pub internal_node_count: usize,
    /// Total size of values held by the cache.
    pub leaf_value_size: usize,
}

/// Used to fetch proofs from a remote tree via the ReadSyncer interface.
pub trait ReadSyncFetcher {
    /// Fetch proof.
    fn fetch(
        &self,
        ctx: Context,
        root: Root,
        ptr: NodePtrRef,
        rs: &mut Box<dyn ReadSync>,
    ) -> Fallible<Proof>;
}

impl<F> ReadSyncFetcher for F
where
    F: Fn(Context, Root, NodePtrRef, &mut Box<dyn ReadSync>) -> Fallible<Proof>,
{
    fn fetch(
        &self,
        ctx: Context,
        root: Root,
        ptr: NodePtrRef,
        rs: &mut Box<dyn ReadSync>,
    ) -> Fallible<Proof> {
        (*self)(ctx, root, ptr, rs)
    }
}

/// Cache interface for the in-mmory tree cache.
pub trait Cache {
    /// Return `self` as an `Any` object, useful for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Return statistics about the contents of the cache.
    fn stats(&self) -> CacheStats;

    /// Get a pointer to the current uncommitted root node.
    fn get_pending_root(&self) -> NodePtrRef;
    /// Set the root node for the tree to the given pointer.
    fn set_pending_root(&mut self, new_root: NodePtrRef);
    /// Get the root of the tree used for syncing.
    fn get_sync_root(&self) -> Root;
    /// Set the root of the tree after committing.
    fn set_sync_root(&mut self, root: Root);

    /// Get the read syncer backing this cache.
    fn get_read_syncer(&self) -> &Box<dyn ReadSync>;

    /// Create a new internal node and returns a pointer to it.
    fn new_internal_node(
        &mut self,
        label: &Key,
        label_bit_length: Depth,
        leaf_node: NodePtrRef,
        left: NodePtrRef,
        right: NodePtrRef,
    ) -> NodePtrRef;
    /// Create a new leaf node and returns a pointer to it.
    fn new_leaf_node(&mut self, key: &Key, value: Value) -> NodePtrRef;

    /// Try removing a node from the cache.
    fn remove_node(&mut self, ptr: NodePtrRef);

    /// Dereference a node pointer into a concrete node object.
    ///
    /// Calling this method may invoke the underlying read syncer.
    /// Giving a None fetcher forces the dereference to be local-only,
    /// without invoking the read syncer.
    fn deref_node_ptr<F: ReadSyncFetcher>(
        &mut self,
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        fetcher: Option<F>,
    ) -> Fallible<Option<NodeRef>>;
    /// Perform a remote sync with the configured remote syncer.
    fn remote_sync<F: ReadSyncFetcher>(
        &mut self,
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        fetcher: F,
    ) -> Fallible<()>;

    /// Mark that a tree node was just used.
    fn use_node(&mut self, ptr: NodePtrRef) -> bool;

    /// Commit a node into the cache.
    ///
    /// This method may evict some nodes in order to make space
    /// for the one being committed.
    fn commit_node(&mut self, ptr: NodePtrRef);

    // Mark a tree node as no longer being eligible for eviction
    // due to it becoming dirty.
    fn rollback_node(&mut self, ptr: NodePtrRef, kind: NodeKind);

    /// Mark the current LRU queue positions as the ones before any nodes are
    /// visited. Any new nodes committed into the cache after this is called
    /// will be inserted after the marked position.
    ///
    /// This makes it possible to keep the path from the root to the derefed
    /// node in the cache instead of evicting it.
    fn mark_position(&mut self);
}

/// Shorthand for the type that cacheable items must hold to aid caching.
pub type CacheExtra<T> = Option<NonNull<CacheItemBox<T>>>;

/// Cacheable objects must implement this trait to enable the cache to cache them.
pub trait CacheItem<Item = Self>
where
    Item: CacheItem + Default,
{
    /// Get the item's caching hint.
    ///
    /// For e.g. the LRU cache, this may be a used timestamp.
    fn get_cache_extra(&self) -> CacheExtra<Item>;
    /// Set the item's caching hint.
    fn set_cache_extra(&mut self, new_val: CacheExtra<Item>);
    /// Return the size, in bytes, of the item when cached.
    fn get_cached_size(&self) -> usize;
}

/// Callback type used for updating cache items after a commit.
pub type CacheUpdater<C> = Box<dyn Fn(&mut C) -> ()>;

/// A list of cache update callbacks.
pub struct UpdateList<C: Cache> {
    updates: Vec<CacheUpdater<C>>,
}

impl<C: Cache> UpdateList<C> {
    /// Construct a new UpdateList instance.
    pub fn new() -> UpdateList<C> {
        UpdateList {
            updates: Vec::new(),
        }
    }

    /// Push a new callback to the end of the list.
    pub fn push(&mut self, updater: CacheUpdater<C>) {
        self.updates.push(updater);
    }

    /// Commit the update list by calling all callbacks in order and destroying the list.
    pub fn commit(&mut self, cache: &mut C) {
        for update in &self.updates {
            (update)(cache);
        }
        self.updates.clear();
    }
}
