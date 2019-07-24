use std::{any::Any, ptr::NonNull, sync::Arc};

use failure::Fallible;
use io_context::Context;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{cache::lru_cache::CacheItemBox, sync::*, tree::*},
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
    fn get_pending_root(&self) -> NodePtrRef;
    /// Set the root node for the tree to the given pointer.
    fn set_pending_root(&mut self, new_root: NodePtrRef);
    /// Get the root of the tree used for syncing.
    fn get_sync_root(&self) -> Root;
    /// Set the root of the tree after committing.
    fn set_sync_root(&mut self, root: Root);

    /// Set the maximum depth for subtree prefetch.
    fn set_prefetch_depth(&mut self, depth: Depth);
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
    fn new_leaf_node(&mut self, key: &Key, val: Value) -> NodePtrRef;
    /// Create a new value object and returns a pointer to it.
    fn new_value(&mut self, val: Value) -> ValuePtrRef;

    /// Try removing a node from the cache.
    fn remove_node(&mut self, ptr: NodePtrRef);
    /// Remove a value from the cache.
    fn remove_value(&mut self, ptr: ValuePtrRef);

    /// Returns the node spelled out by id.path of length id.bit_depth.
    ///
    /// Beside the node, this function also returns bit depth of the node's parent.
    ///
    /// id.Path.len() must always be at least id.bit_depth/8 bytes long.
    ///
    /// If there is an InternalNode and its LeafNode spelled out by the same id, then this function
    /// returns an InternalNode. If id is empty, then this function returns the root.
    ///
    /// WARNING: If the requested node does not exist in the tree, this function
    /// returns either nil or some other arbitrary node.
    fn deref_node_id(
        &mut self,
        ctx: &Arc<Context>,
        node_id: NodeID,
    ) -> Fallible<(NodePtrRef, Depth)>;
    /// Dereference a node pointer into a concrete node object.
    ///
    /// Calling this method may invoke the underlying read syncer.
    fn deref_node_ptr(
        &mut self,
        ctx: &Arc<Context>,
        node_id: NodeID,
        node_ptr: NodePtrRef,
        key: Option<&Key>,
    ) -> Fallible<Option<NodeRef>>;
    /// Dereference a value pointer into a concrete value.
    ///
    /// Calling this method may invoke the underlying read syncer.
    fn deref_value_ptr(&mut self, ctx: &Arc<Context>, val: ValuePtrRef) -> Fallible<Option<Value>>;

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

    // Mark a tree node as no longer being eligible for eviction
    // due to it becoming dirty.
    fn rollback_node(&mut self, ptr: NodePtrRef, kind: NodeKind);

    /// Reconstruct a subtree of nodes and return a pointer to its root.
    ///
    /// Call this to resurrect a subtree summary as returned by a read syncer.
    fn reconstruct_subtree(
        &mut self,
        ctx: &Arc<Context>,
        root: Hash,
        st: &Subtree,
        depth: Depth,
        max_depth: Depth,
    ) -> Fallible<NodePtrRef>;

    /// Prefetch a subtree from the read syncer.
    fn prefetch(
        &mut self,
        ctx: &Arc<Context>,
        subtree_root: Hash,
        subtree_path: Key,
        depth: Depth,
    ) -> Fallible<NodePtrRef>;
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
