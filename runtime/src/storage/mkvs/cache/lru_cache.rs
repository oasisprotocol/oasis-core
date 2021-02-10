use std::{any::Any, cell::RefCell, pin::Pin, ptr::NonNull, rc::Rc, sync::Arc};

use anyhow::{anyhow, Result};
use intrusive_collections::{IntrusivePointer, LinkedList, LinkedListLink};
use io_context::Context;
use thiserror::Error;

use crate::storage::mkvs::{cache::*, sync::*, tree::*};

#[derive(Error, Debug)]
#[error("mkvs: tried to remove locked node")]
struct RemoveLockedError;

#[derive(Clone, Default)]
pub struct CacheItemBox<Item: CacheItem + Default> {
    item: Rc<RefCell<Item>>,
    link: LinkedListLink,
}

unsafe impl<T: CacheItem + Default> IntrusivePointer<CacheItemBox<T>>
    for Pin<Box<CacheItemBox<T>>>
{
    #[inline]
    fn into_raw(self) -> *const CacheItemBox<T> {
        unsafe { Box::into_raw(Pin::into_inner_unchecked(self)) }
    }
    #[inline]
    unsafe fn from_raw(ptr: *const CacheItemBox<T>) -> Self {
        Box::into_pin(Box::from_raw(ptr as *mut CacheItemBox<T>))
    }
}

intrusive_adapter!(
    CacheItemAdapter<Item> = Pin<Box<CacheItemBox<Item>>>:
        CacheItemBox<Item> { link: LinkedListLink }
        where Item: CacheItem + Default
);

struct LRUList<V>
where
    V: CacheItem + Default,
{
    pub list: LinkedList<CacheItemAdapter<V>>,
    pub size: usize,
    pub capacity: usize,
    pub mark: CacheExtra<V>,
}

impl<V> LRUList<V>
where
    V: CacheItem + Default,
{
    pub fn new(capacity: usize) -> LRUList<V> {
        LRUList {
            list: LinkedList::new(CacheItemAdapter::new()),
            size: 0,
            capacity: capacity,
            mark: None,
        }
    }

    fn mark(&mut self) {
        self.mark = self.list.front().get().map(|front| {
            front
                .item
                .borrow()
                .get_cache_extra()
                .expect("item was just retrieved from list, cache extra must exist")
        });
    }

    fn add(&mut self, val: Rc<RefCell<V>>) {
        let mut val_ref = val.borrow_mut();
        if val_ref.get_cache_extra().is_none() {
            self.size += val_ref.get_cached_size();
            let mut item_box = Box::pin(CacheItemBox {
                item: val.clone(),
                link: LinkedListLink::new(),
            });
            val_ref.set_cache_extra(NonNull::new(&mut *item_box));
            if let Some(non_null_pos) = &self.mark {
                let mut pos_cursor =
                    unsafe { self.list.cursor_mut_from_ptr(non_null_pos.as_ptr()) };
                pos_cursor.insert_after(item_box);
            } else {
                self.list.push_front(item_box);
            }
        } else {
            self.use_val(val.clone());
        }
    }

    fn use_val(&mut self, val: Rc<RefCell<V>>) -> bool {
        let val_ref = val.borrow();
        match val_ref.get_cache_extra() {
            None => false,
            Some(non_null) => {
                let mut item_cursor = unsafe { self.list.cursor_mut_from_ptr(non_null.as_ptr()) };
                let removed_box = item_cursor.remove().unwrap();
                self.list.push_front(removed_box);
                true
            }
        }
    }

    fn remove(&mut self, val: Rc<RefCell<V>>) -> bool {
        let extra = val.borrow().get_cache_extra();
        match extra {
            None => false,
            Some(non_null) => {
                if let Some(non_null_mark) = self.mark {
                    if non_null.as_ptr() == non_null_mark.as_ptr() {
                        self.mark = None;
                    }
                }

                let mut item_cursor = unsafe { self.list.cursor_mut_from_ptr(non_null.as_ptr()) };
                match item_cursor.remove() {
                    None => false,
                    Some(item_box) => {
                        let mut val = item_box.item.borrow_mut();
                        val.set_cache_extra(None);
                        self.size -= val.get_cached_size();
                        true
                    }
                }
            }
        }
    }

    fn evict_for_val(
        &mut self,
        val: Rc<RefCell<V>>,
        locked_val: Option<&Rc<RefCell<V>>>,
    ) -> Result<Vec<Rc<RefCell<V>>>, RemoveLockedError> {
        let mut evicted: Vec<Rc<RefCell<V>>> = Vec::new();
        if self.capacity > 0 {
            let target_size = val.borrow().get_cached_size();
            while !self.list.is_empty() && self.size + target_size > self.capacity {
                let back = (*self.list.back().get().unwrap()).item.clone();
                if let Some(locked_val) = locked_val {
                    if back.as_ptr() == locked_val.as_ptr() {
                        return Err(RemoveLockedError);
                    }
                }
                if self.remove(back.clone()) {
                    evicted.push(back);
                }
            }
        }
        Ok(evicted)
    }
}

/// Cache implementation with a simple LRU eviction strategy.
pub struct LRUCache {
    read_syncer: Box<dyn ReadSync>,

    pending_root: NodePtrRef,
    sync_root: Root,

    lru_leaf: LRUList<NodePointer>,
    lru_internal: LRUList<NodePointer>,
}

impl LRUCache {
    /// Construct a new cache instance.
    ///
    /// * `node_capacity` is the maximum number of internal nodes held by the
    ///   cache before eviction.
    /// * `value_capacity` is the total size, in bytes, of values held
    ///   by the cache before eviction.
    /// * `read_syncer` is the read syncer used as backing for the cache.
    pub fn new(
        node_capacity: usize,
        value_capacity: usize,
        read_syncer: Box<dyn ReadSync>,
        root_type: RootType,
    ) -> Box<LRUCache> {
        Box::new(LRUCache {
            read_syncer: read_syncer,

            pending_root: Rc::new(RefCell::new(NodePointer {
                node: None,
                ..Default::default()
            })),
            sync_root: Root {
                root_type: root_type,
                ..Default::default()
            },

            lru_leaf: LRUList::new(value_capacity),
            lru_internal: LRUList::new(node_capacity),
        })
    }

    fn new_internal_node_ptr(&mut self, node: Option<NodeRef>) -> NodePtrRef {
        Rc::new(RefCell::new(NodePointer {
            node: node,
            ..Default::default()
        }))
    }

    fn new_leaf_node_ptr(&mut self, node: Option<NodeRef>) -> NodePtrRef {
        Rc::new(RefCell::new(NodePointer {
            node: node,
            ..Default::default()
        }))
    }

    fn try_commit_node(
        &mut self,
        ptr: NodePtrRef,
        locked_ptr: Option<&NodePtrRef>,
    ) -> Result<(), RemoveLockedError> {
        if !ptr.borrow().clean {
            panic!("mkvs: commit_node called on dirty node");
        }
        if ptr.borrow().node.is_none() {
            return Ok(());
        }
        if self.use_node(ptr.clone()) {
            return Ok(());
        }

        match classify_noderef!(? ptr.borrow().node) {
            NodeKind::Internal => {
                let evicted = self
                    .lru_internal
                    .evict_for_val(ptr.clone(), locked_ptr.clone())?;
                for node in evicted {
                    self.try_remove_node(node.clone(), locked_ptr.clone())?;
                }
                self.lru_internal.add(ptr.clone());
            }
            NodeKind::Leaf => {
                let evicted = self
                    .lru_leaf
                    .evict_for_val(ptr.clone(), locked_ptr.clone())?;
                for node in evicted {
                    self.try_remove_node(node.clone(), locked_ptr.clone())?;
                }
                self.lru_leaf.add(ptr.clone());
            }
            NodeKind::None => return Ok(()),
        };

        Ok(())
    }

    fn try_remove_node(
        &mut self,
        ptr: NodePtrRef,
        locked_ptr: Option<&NodePtrRef>,
    ) -> Result<(), RemoveLockedError> {
        #[derive(Clone, Copy)]
        enum VisitState {
            Unvisited,
            VisitedLeaf,
            VisitedLeft,
            VisitedRight,
        }
        #[derive(Clone)]
        struct PendingNode(NodePtrRef, VisitState);

        let mut stack: Vec<PendingNode> = Vec::new();
        stack.push(PendingNode(ptr, VisitState::Unvisited));
        'stack: while !stack.is_empty() {
            let top_idx = stack.len() - 1;
            let top = stack[top_idx].clone();

            if let Some(locked_ptr) = locked_ptr {
                if locked_ptr.as_ptr() == top.0.as_ptr() {
                    return Err(RemoveLockedError);
                }
            }

            // Perform removal in depth-first order. We do not remove the node from
            // the stack until all of its subtrees have been fully removed.
            if let Some(ref node_ref) = top.0.borrow().node {
                if let NodeBox::Internal(ref n) = *node_ref.borrow() {
                    match top.1 {
                        VisitState::Unvisited => {
                            stack[top_idx].1 = VisitState::VisitedLeaf;
                            stack.push(PendingNode(n.leaf_node.clone(), VisitState::Unvisited));
                            continue 'stack;
                        }
                        VisitState::VisitedLeaf => {
                            stack[top_idx].1 = VisitState::VisitedLeft;
                            stack.push(PendingNode(n.left.clone(), VisitState::Unvisited));
                            continue 'stack;
                        }
                        VisitState::VisitedLeft => {
                            stack[top_idx].1 = VisitState::VisitedRight;
                            stack.push(PendingNode(n.right.clone(), VisitState::Unvisited));
                            continue 'stack;
                        }
                        VisitState::VisitedRight => {
                            // Now it can finally be removed.
                        }
                    }
                }
            }

            stack.pop();

            match classify_noderef!(? top.0.borrow().node) {
                NodeKind::Internal => {
                    self.lru_internal.remove(top.0.clone());
                    top.0.borrow_mut().node = None;
                }
                NodeKind::Leaf => {
                    self.lru_leaf.remove(top.0.clone());
                    top.0.borrow_mut().node = None;
                }
                NodeKind::None => {}
            }
        }

        Ok(())
    }

    fn commit_merged_node(
        &mut self,
        ptr: NodePtrRef,
        locked_ptr: &NodePtrRef,
    ) -> Result<(), RemoveLockedError> {
        // Try to commit the node. If we fail this means that there is not enough
        // space in the cache to keep the node that we are trying to dereference.
        if let Err(error) = self.try_commit_node(ptr.clone(), Some(locked_ptr)) {
            // Failed to commit, make sure to not keep the subtree in memory.
            ptr.borrow_mut().node = None;
            return Err(error);
        }

        // Commit all children.
        match classify_noderef!(? ptr.borrow().node) {
            NodeKind::Internal => {
                let node_ref = ptr.borrow().get_node();
                self.commit_merged_node(noderef_as!(node_ref, Internal).left.clone(), &locked_ptr)?;
                self.commit_merged_node(
                    noderef_as!(node_ref, Internal).right.clone(),
                    &locked_ptr,
                )?;
            }
            NodeKind::Leaf => {}
            NodeKind::None => {}
        }

        Ok(())
    }
}

impl Cache for LRUCache {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn stats(&self) -> CacheStats {
        CacheStats {
            internal_node_count: self.lru_internal.size,
            leaf_value_size: self.lru_leaf.size,
        }
    }

    fn get_pending_root(&self) -> NodePtrRef {
        self.pending_root.clone()
    }

    fn set_pending_root(&mut self, new_root: NodePtrRef) {
        self.pending_root = new_root.clone();
    }

    fn get_sync_root(&self) -> Root {
        self.sync_root.clone()
    }

    fn set_sync_root(&mut self, root: Root) {
        self.sync_root = root;
    }

    fn get_read_syncer(&self) -> &Box<dyn ReadSync> {
        &self.read_syncer
    }

    fn new_internal_node(
        &mut self,
        label: &Key,
        label_bit_length: Depth,
        leaf_node: NodePtrRef,
        left: NodePtrRef,
        right: NodePtrRef,
    ) -> NodePtrRef {
        let node = Rc::new(RefCell::new(NodeBox::Internal(InternalNode {
            label: label.clone(),
            label_bit_length: label_bit_length,
            leaf_node: leaf_node,
            left: left,
            right: right,
            ..Default::default()
        })));
        self.new_internal_node_ptr(Some(node))
    }

    fn new_leaf_node(&mut self, key: &Key, value: Value) -> NodePtrRef {
        let node = Rc::new(RefCell::new(NodeBox::Leaf(LeafNode {
            key: key.clone(),
            value,
            ..Default::default()
        })));
        self.new_leaf_node_ptr(Some(node))
    }

    fn remove_node(&mut self, ptr: NodePtrRef) {
        self.try_remove_node(ptr, None)
            .expect("no locked pointer passed, cannot fail");
    }

    fn deref_node_ptr<F: ReadSyncFetcher>(
        &mut self,
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        fetcher: Option<F>,
    ) -> Result<Option<NodeRef>> {
        let ptr_ref = ptr;
        let ptr = ptr_ref.borrow();

        self.use_node(ptr_ref.clone());

        if let Some(ref node) = &ptr.node {
            let refetch = match *node.borrow() {
                NodeBox::Internal(ref n) => {
                    // If this is an internal node, check if the leaf node  has been evicted.
                    // In this case treat it as if we need to re-fetch the node.
                    let leaf_ptr = n.leaf_node.borrow();
                    !leaf_ptr.is_null() && leaf_ptr.node.is_none()
                }
                NodeBox::Leaf(..) => false,
            };

            if refetch {
                drop(ptr);
                self.remove_node(ptr_ref.clone());
            } else {
                return Ok(Some(node.clone()));
            }
        } else {
            if !ptr.clean || ptr.is_null() {
                return Ok(None);
            }
            drop(ptr);
        }

        // Node not available locally, fetch from read syncer.
        if let Some(fetcher) = fetcher {
            self.remote_sync(ctx, ptr_ref.clone(), fetcher)?;
        } else {
            return Err(anyhow!(
                "mkvs: node to dereference not available locally and no fetcher provided"
            ));
        }

        let ptr = ptr_ref.borrow();
        if ptr.node.is_none() {
            return Err(anyhow!(
                "mkvs: received result did not contain node (or cache too small)"
            ));
        }
        Ok(ptr.node.clone())
    }

    fn remote_sync<F: ReadSyncFetcher>(
        &mut self,
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        fetcher: F,
    ) -> Result<()> {
        let proof = fetcher.fetch(
            Context::create_child(&ctx),
            self.sync_root,
            ptr.clone(),
            &mut self.read_syncer,
        )?;

        // The proof can be for one of two hashes: i) it is either for ptr.Hash in case
        // all the nodes are only contained in the subtree below ptr, or ii) it is for
        // the c.syncRoot.Hash in case it contains nodes outside the subtree.
        let ptr_hash = ptr.borrow().hash;
        let (dst_ptr, expected_root) = if proof.untrusted_root == ptr_hash {
            (ptr.clone(), ptr_hash)
        } else if proof.untrusted_root == self.sync_root.hash {
            (self.pending_root.clone(), self.sync_root.hash)
        } else {
            return Err(anyhow!(
                "mkvs: got proof for unexpected root ({:?})",
                proof.untrusted_root
            ));
        };

        // Verify proof.
        let pv = ProofVerifier;
        let subtree = pv.verify_proof(Context::create_child(&ctx), expected_root, &proof)?;

        // Merge resulting nodes.
        let mut merged_nodes: Vec<NodePtrRef> = Vec::new();
        merge_verified_subtree(dst_ptr, subtree, &mut merged_nodes)?;
        let mut remove = false;
        for node_ref in merged_nodes {
            if remove {
                // Do not keep subtrees that we failed to commit in memory.
                node_ref.borrow_mut().node = None;
            }

            if let Err(RemoveLockedError) = self.commit_merged_node(node_ref, &ptr) {
                // Cache is too small, ignore.
                remove = true;
            }
        }

        Ok(())
    }

    fn use_node(&mut self, ptr: NodePtrRef) -> bool {
        match classify_noderef!(? ptr.borrow().node) {
            NodeKind::Internal => self.lru_internal.use_val(ptr),
            NodeKind::Leaf => self.lru_leaf.use_val(ptr),
            NodeKind::None => false,
        }
    }

    fn commit_node(&mut self, ptr: NodePtrRef) {
        self.try_commit_node(ptr, None)
            .expect("no locked pointer passed, cannot fail");
    }

    fn rollback_node(&mut self, ptr: NodePtrRef, kind: NodeKind) {
        if ptr.borrow().get_cache_extra().is_none() {
            // Node has not yet been committed to cache.
            return;
        }

        let lru = match kind {
            NodeKind::Internal => &mut self.lru_internal,
            NodeKind::Leaf => &mut self.lru_leaf,
            NodeKind::None => panic!("lru_cache: rollback works only for Internal and Leaf nodes!"),
        };
        lru.remove(ptr.clone());

        ptr.borrow_mut().set_cache_extra(None);
    }

    fn mark_position(&mut self) {
        self.lru_internal.mark();
        self.lru_leaf.mark();
    }
}
