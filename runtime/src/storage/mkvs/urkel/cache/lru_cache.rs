use std::{any::Any, cell::RefCell, pin::Pin, ptr::NonNull, rc::Rc, sync::Arc};

use failure::Fallible;
use intrusive_collections::{IntrusivePointer, LinkedList, LinkedListLink};
use io_context::Context;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{cache::*, sync::*, tree::*, utils::*},
};

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
        }
    }

    fn add_to_front(&mut self, val: Rc<RefCell<V>>) {
        let mut val_ref = val.borrow_mut();
        if val_ref.get_cache_extra().is_none() {
            self.size += val_ref.get_cached_size();
            let mut item_box = Box::pin(CacheItemBox {
                item: val.clone(),
                link: LinkedListLink::new(),
            });
            val_ref.set_cache_extra(NonNull::new(&mut *item_box));
            self.list.push_front(item_box);
        } else {
            self.move_to_front(val.clone());
        }
    }

    fn move_to_front(&mut self, val: Rc<RefCell<V>>) -> bool {
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

    fn evict_for_val(&mut self, val: Rc<RefCell<V>>) -> Vec<Rc<RefCell<V>>> {
        let mut evicted: Vec<Rc<RefCell<V>>> = Vec::new();
        if self.capacity > 0 {
            let target_size = val.borrow().get_cached_size();
            while !self.list.is_empty() && self.size + target_size > self.capacity {
                let back = (*self.list.back().get().unwrap()).item.clone();
                if self.remove(back.clone()) {
                    evicted.push(back);
                }
            }
        }
        evicted
    }
}

/// Cache implementation with a simple LRU eviction strategy.
pub struct LRUCache {
    read_syncer: Box<dyn ReadSync>,

    pending_root: NodePtrRef,
    sync_root: Hash,

    internal_node_count: u64,
    leaf_node_count: u64,

    prefetch_depth: u8,

    lru_values: LRUList<ValuePointer>,
    lru_nodes: LRUList<NodePointer>,
}

impl LRUCache {
    /// Construct a new cache instance.
    ///
    /// * `node_capacity` is the maximum number of nodes held by the
    ///   cache before eviction.
    /// * `value_capacity` is the total size, in bytes, of values held
    ///   by the cache before eviction.
    /// * `read_syncer` is the read syncer used as backing for the cache.
    pub fn new(
        node_capacity: usize,
        value_capacity: usize,
        read_syncer: Box<dyn ReadSync>,
    ) -> Box<LRUCache> {
        Box::new(LRUCache {
            read_syncer: read_syncer,

            pending_root: Rc::new(RefCell::new(NodePointer {
                node: None,
                ..Default::default()
            })),
            sync_root: Hash::default(),

            internal_node_count: 0,
            leaf_node_count: 0,

            prefetch_depth: 0,

            lru_values: LRUList::new(value_capacity),
            lru_nodes: LRUList::new(node_capacity),
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

    fn new_value_ptr(&self, val: Value) -> ValuePtrRef {
        Rc::new(RefCell::new(ValuePointer {
            value: Some(val.clone()),
            ..Default::default()
        }))
    }

    fn use_node(&mut self, node: NodePtrRef) -> bool {
        self.lru_nodes.move_to_front(node)
    }

    fn subtract_node(&mut self, ptr: NodePtrRef) {
        let mut ptr = ptr.borrow_mut();
        if ptr.is_null() {
            return;
        }
        if let Some(ref node) = ptr.node {
            match *node.borrow() {
                NodeBox::Internal(_) => {
                    self.internal_node_count -= 1;
                }
                NodeBox::Leaf(ref n) => {
                    self.remove_value(n.value.clone());
                    self.leaf_node_count -= 1;
                }
            };
            ptr.node = None;
        }
    }

    fn use_value(&mut self, val: ValuePtrRef) -> bool {
        self.lru_values.move_to_front(val)
    }

    fn _reconstruct_summary(
        &mut self,
        st: &Subtree,
        sptr: &SubtreePointer,
        depth: u8,
        max_depth: u8,
    ) -> Fallible<NodePtrRef> {
        if depth > max_depth {
            return Err(CacheError::MaximumDepthExceeded.into());
        }

        if !sptr.valid {
            return Err(CacheError::InvalidSubtreePointer.into());
        }

        if sptr.full {
            let node_ref = st.get_full_node_at(sptr.index)?;
            return match *node_ref.borrow_mut() {
                NodeBox::Internal(ref mut int) => {
                    int.clean = false;
                    Ok(self.new_internal_node_ptr(Some(node_ref.clone())))
                }
                NodeBox::Leaf(ref mut leaf) => {
                    leaf.clean = false;
                    Ok(self.new_leaf_node_ptr(Some(node_ref.clone())))
                }
            };
        } else {
            let summary = st.get_summary_at(sptr.index)?;
            return match summary {
                None => Ok(NodePointer::null_ptr()),
                Some(summary) => {
                    let left =
                        self._reconstruct_summary(st, &summary.left, depth + 1, max_depth)?;
                    let right =
                        self._reconstruct_summary(st, &summary.right, depth + 1, max_depth)?;
                    Ok(self.new_internal_node(left, right))
                }
            };
        }
    }
}

impl Cache for LRUCache {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn stats(&self) -> CacheStats {
        CacheStats {
            internal_node_count: self.internal_node_count,
            leaf_node_count: self.leaf_node_count,
            leaf_value_size: self.lru_values.size,
        }
    }

    fn get_pending_root(&self) -> NodePtrRef {
        self.pending_root.clone()
    }

    fn set_pending_root(&mut self, new_root: NodePtrRef) {
        self.pending_root = new_root.clone();
    }

    fn set_sync_root(&mut self, new_hash: Hash) {
        self.sync_root = new_hash;
    }

    fn set_prefetch_depth(&mut self, depth: u8) {
        self.prefetch_depth = depth;
    }

    fn get_read_syncer(&self) -> &Box<dyn ReadSync> {
        &self.read_syncer
    }

    fn new_internal_node(&mut self, left: NodePtrRef, right: NodePtrRef) -> NodePtrRef {
        let node = Rc::new(RefCell::new(NodeBox::Internal(InternalNode {
            left: left,
            right: right,
            ..Default::default()
        })));
        self.new_internal_node_ptr(Some(node))
    }

    fn new_leaf_node(&mut self, key: Hash, val: Value) -> NodePtrRef {
        let node = Rc::new(RefCell::new(NodeBox::Leaf(LeafNode {
            key: key.clone(),
            value: self.new_value(val),
            ..Default::default()
        })));
        self.new_leaf_node_ptr(Some(node))
    }

    fn new_value(&mut self, val: Value) -> ValuePtrRef {
        self.new_value_ptr(val)
    }

    fn remove_node(&mut self, ptr: NodePtrRef) {
        let mut stack: Vec<NodePtrRef> = Vec::new();
        stack.push(ptr);
        while !stack.is_empty() {
            let top = stack[stack.len() - 1].clone();

            if top.borrow().get_cache_extra().is_none() {
                stack.pop();
                continue;
            }

            if let Some(ref node_ref) = top.borrow().node {
                if let NodeBox::Internal(ref n) = *node_ref.borrow() {
                    if n.left.borrow().has_node() {
                        stack.push(n.left.clone());
                        n.left.borrow_mut().node = None;
                        continue;
                    }
                    if n.right.borrow().has_node() {
                        stack.push(n.right.clone());
                        n.right.borrow_mut().node = None;
                        continue;
                    }
                }
                if let NodeBox::Leaf(ref n) = *node_ref.borrow() {
                    self.remove_value(n.value.clone());
                }
            }

            stack.pop();

            if self.lru_nodes.remove(top.clone()) {
                self.subtract_node(top);
            }
        }
    }

    fn remove_value(&mut self, ptr: ValuePtrRef) {
        self.lru_values.remove(ptr);
    }

    fn deref_node_id(&mut self, ctx: &Arc<Context>, node_id: NodeID) -> Fallible<NodePtrRef> {
        let mut cur_ptr = self.pending_root.clone();
        for d in 0..node_id.depth {
            let node = self.deref_node_ptr(ctx, node_id.at_depth(d), cur_ptr.clone(), None)?;
            let node = match node {
                None => return Ok(NodePointer::null_ptr()),
                Some(node) => node,
            };

            if let NodeBox::Internal(ref n) = *node.borrow() {
                if get_key_bit(&node_id.path, d) {
                    cur_ptr = n.right.clone();
                } else {
                    cur_ptr = n.left.clone();
                }
            };
        }
        Ok(cur_ptr)
    }

    fn deref_node_ptr(
        &mut self,
        ctx: &Arc<Context>,
        node_id: NodeID,
        ptr: NodePtrRef,
        key: Option<Hash>,
    ) -> Fallible<Option<NodeRef>> {
        let ptr_ref = ptr;
        let ptr = ptr_ref.borrow();
        if let Some(ref node) = &ptr.node {
            // If this is a leaf node, check if the value has been evicted. In this case
            // treat it as if we need to re-fetch the node.
            if let NodeBox::Leaf(ref n) = *node.borrow() {
                if n.value.borrow().value == None {
                    self.remove_node(ptr_ref.clone());
                } else {
                    self.use_node(ptr_ref.clone());
                    return Ok(Some(node.clone()));
                }
            } else {
                self.use_node(ptr_ref.clone());
                return Ok(Some(node.clone()));
            }
        }
        if !ptr.clean || ptr.is_null() {
            return Ok(None);
        }
        drop(ptr);

        let mut ptr = ptr_ref.borrow_mut();
        match key {
            None => {
                let node_ref = self.read_syncer.get_node(
                    Context::create_child(ctx),
                    self.sync_root,
                    node_id,
                )?;
                node_ref.borrow_mut().validate(ptr.hash)?;
                ptr.node = Some(node_ref.clone());
            }
            Some(key) => {
                let subtree = self.read_syncer.get_path(
                    Context::create_child(ctx),
                    self.sync_root,
                    key,
                    node_id.depth,
                )?;
                let new_ptr = self.reconstruct_subtree(
                    ctx,
                    ptr.hash,
                    &subtree,
                    node_id.depth,
                    (8 * Hash::len() - 1) as u8,
                )?;
                let new_ptr = new_ptr.borrow();
                ptr.clean = new_ptr.clean;
                ptr.hash = new_ptr.hash;
                ptr.node = new_ptr.node.clone();
            }
        };

        Ok(ptr.node.clone())
    }

    fn deref_value_ptr(
        &mut self,
        _ctx: &Arc<Context>,
        val: ValuePtrRef,
    ) -> Fallible<Option<Value>> {
        if self.use_value(val.clone()) || val.borrow().value != None {
            return Ok(val.borrow().value.clone());
        }

        if !val.borrow().clean {
            return Ok(None);
        }

        // A leaf node should always also contain a value.
        panic!("urkel: leaf node does not contain value");
    }

    fn commit_node(&mut self, ptr: NodePtrRef) {
        if !ptr.borrow().clean {
            panic!("urkel: commit_node called on dirty node");
        }
        if ptr.borrow().node.is_none() {
            return;
        }
        if self.use_node(ptr.clone()) {
            return;
        }

        for node in self.lru_nodes.evict_for_val(ptr.clone()).iter() {
            self.subtract_node(node.clone());
        }
        self.lru_nodes.add_to_front(ptr.clone());

        if let Some(ref some_node) = ptr.borrow().node {
            match *some_node.borrow() {
                NodeBox::Internal(_) => self.internal_node_count += 1,
                NodeBox::Leaf(_) => self.leaf_node_count += 1,
            };
        }
    }

    fn commit_value(&mut self, ptr: ValuePtrRef) {
        if !ptr.borrow().clean {
            panic!("urkel: commit_value called on dirty value");
        }
        if self.use_value(ptr.clone()) {
            return;
        }
        if let None = ptr.borrow().value {
            return;
        }

        self.lru_values.evict_for_val(ptr.clone());
        self.lru_values.add_to_front(ptr.clone());
    }

    fn reconstruct_subtree(
        &mut self,
        ctx: &Arc<Context>,
        root: Hash,
        st: &Subtree,
        depth: u8,
        max_depth: u8,
    ) -> Fallible<NodePtrRef> {
        let ptr = self._reconstruct_summary(st, &st.root, depth, max_depth)?;
        if ptr.borrow().is_null() {
            return Err(CacheError::ReconstructedRootNil.into());
        }

        let mut update_list: UpdateList<LRUCache> = UpdateList::new();
        let new_root = _commit(ctx, ptr.clone(), &mut update_list)?;
        if new_root != root {
            Err(CacheError::SyncerBadRoot {
                expected_root: root,
                returned_root: new_root,
            }
            .into())
        } else {
            update_list.commit(self);
            Ok(ptr)
        }
    }

    fn prefetch(
        &mut self,
        ctx: &Arc<Context>,
        subtree_root: Hash,
        subtree_path: Hash,
        depth: u8,
    ) -> Fallible<NodePtrRef> {
        if self.prefetch_depth == 0 {
            return Ok(NodePointer::null_ptr());
        }

        let result = self.read_syncer.get_subtree(
            Context::create_child(ctx),
            self.sync_root,
            NodeID {
                path: subtree_path,
                depth: depth,
            },
            self.prefetch_depth,
        );

        let st = match result {
            Err(err) => {
                if let Some(sync_err) = err.downcast_ref::<SyncerError>() {
                    if let SyncerError::Unsupported = sync_err {
                        return Ok(NodePointer::null_ptr());
                    }
                }
                return Err(err);
            }
            Ok(ref st) => st,
        };
        self.reconstruct_subtree(ctx, subtree_root, st, 0, self.prefetch_depth)
    }
}
