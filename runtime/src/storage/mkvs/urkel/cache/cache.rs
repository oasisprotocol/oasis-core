use std::any::Any;

use failure::Fallible;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{sync::*, tree::*},
};

/// Statistics about the contents of the cache.
#[derive(Debug, Default)]
pub struct CacheStats {
    /// Count of internal nodes held by the cache.
    pub internal_node_count: u64,
    /// Count of leaf nodes held by the cache.
    pub leaf_node_count: u64,
    /// Total size of values held by the cache.
    pub leaf_value_size: usize,
}

/// Cache interface for the in-mmory tree cache.
pub trait Cache {
    /// Return `self` as an `Any` object, useful for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Return statistics about the contents of the cache.
    fn stats(&self) -> CacheStats;

    /// Get a pointer to the current uncommitted root node.
    fn get_pending_root(&mut self) -> NodePtrRef;
    /// Set the root node for the tree to the given pointer.
    fn set_pending_root(&mut self, new_root: NodePtrRef);
    /// Set the root hash of the tree after committing.
    fn set_sync_root(&mut self, new_hash: Hash);

    /// Set the maximum depth for subtree prefetch.
    fn set_prefetch_depth(&mut self, depth: u8);
    /// Get the read syncer backing this cache.
    fn get_read_syncer(&self) -> &Box<dyn ReadSync>;

    /// Create a new internal node and returns a pointer to it.
    fn new_internal_node(&mut self, left: NodePtrRef, right: NodePtrRef) -> NodePtrRef;
    /// Create a new leaf node and returns a pointer to it.
    fn new_leaf_node(&mut self, key: Hash, val: Value) -> NodePtrRef;
    /// Create a new value object and returns a pointer to it.
    fn new_value(&mut self, val: Value) -> ValuePtrRef;

    /// Try removing a node from the cache.
    fn try_remove_node(&mut self, ptr: NodePtrRef);
    /// Remove a value from the cache.
    fn remove_value(&mut self, ptr: ValuePtrRef);

    /// Convert a node path into a node pointer.
    ///
    /// Calling this method may invoke the underlying read syncer.
    fn deref_node_id(&mut self, node_id: NodeID) -> Fallible<NodePtrRef>;
    /// Dereference a node pointer into a concrete node object.
    ///
    /// Calling this method may invoke the underlying read syncer.
    fn deref_node_ptr(
        &mut self,
        node_id: NodeID,
        node_ptr: NodePtrRef,
        key: Option<Hash>,
    ) -> Fallible<Option<NodeRef>>;
    /// Dereference a value pointer into a concrete value.
    ///
    /// Calling this method may invoke the underlying read syncer.
    fn deref_value_ptr(&mut self, val: ValuePtrRef) -> Fallible<Option<Value>>;

    /// Commit a node into the cache.
    ///
    /// This method may evict some nodes in order to make space
    /// for the one being committed.
    fn commit_node(&mut self, ptr: NodePtrRef);
    /// Commit a value into the cache.
    ///
    /// This method may evict some values in order to make space
    /// for the one being committed.
    fn commit_value(&mut self, ptr: ValuePtrRef);

    /// Reconstruct a subtree of nodes and return a pointer to its root.
    ///
    /// Call this to resurrect a subtree summary as returned by a read syncer.
    fn reconstruct_subtree(
        &mut self,
        root: Hash,
        st: &Subtree,
        depth: u8,
        max_depth: u8,
    ) -> Fallible<NodePtrRef>;

    /// Prefetch a subtree from the read syncer.
    fn prefetch(&mut self, root: Hash, depth: u8) -> Fallible<NodePtrRef>;
}

/// Cacheable objects must implement this trait to enable the cache to cache them.
pub trait CacheItem {
    /// Get the item's caching hint.
    ///
    /// For e.g. the LRU cache, this may be a used timestamp.
    fn get_cache_extra(&self) -> u64;
    /// Set the item's caching hint.
    fn set_cache_extra(&mut self, new_val: u64);
    /// Return the size, in bytes, of the item when cached.
    fn get_cached_size(&self) -> usize;
}

/// Callback type used for updating cache items after a commit.
pub type CacheUpdater<C> = Box<Fn(&mut C) -> ()>;

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
