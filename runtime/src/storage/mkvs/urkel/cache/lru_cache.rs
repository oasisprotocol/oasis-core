use std::{any::Any, cell::RefCell, pin::Pin, ptr::NonNull, rc::Rc, sync::Arc};

use failure::Fallible;
use intrusive_collections::{IntrusivePointer, LinkedList, LinkedListLink};
use io_context::Context;

use crate::storage::mkvs::urkel::{cache::*, sync::*, tree::*};

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
    sync_root: Root,

    internal_node_count: u64,
    leaf_node_count: u64,

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
            sync_root: Root::default(),

            internal_node_count: 0,
            leaf_node_count: 0,

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

    fn commit_merged_node(&mut self, ptr: NodePtrRef) {
        // Commit all children.
        match classify_noderef!(? ptr.borrow().node) {
            NodeKind::Internal => {
                let node_ref = ptr.borrow().get_node();
                self.commit_merged_node(noderef_as!(node_ref, Internal).left.clone());
                self.commit_merged_node(noderef_as!(node_ref, Internal).right.clone());
            }
            NodeKind::Leaf => {
                let node_ref = ptr.borrow().get_node();
                self.commit_value(noderef_as!(node_ref, Leaf).value.clone());
            }
            NodeKind::None => {}
        }

        // Commit the node itself.
        self.commit_node(ptr);
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

    fn new_leaf_node(&mut self, key: &Key, val: Value) -> NodePtrRef {
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

    fn deref_node_ptr<F: ReadSyncFetcher>(
        &mut self,
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        fetcher: F,
    ) -> Fallible<Option<NodeRef>> {
        let ptr_ref = ptr;
        let ptr = ptr_ref.borrow();
        if let Some(ref node) = &ptr.node {
            let refetch = match *node.borrow() {
                NodeBox::Internal(ref n) => {
                    // If this is an internal node, check if the leaf node or its value has been
                    // evicted. In this case treat it as if we need to re-fetch the node.
                    let leaf_ptr = n.leaf_node.borrow();
                    if leaf_ptr.is_null() {
                        false
                    } else if let Some(ref int_leaf_node) = &leaf_ptr.node {
                        if let NodeBox::Leaf(ref int_leaf) = *int_leaf_node.borrow() {
                            int_leaf.value.borrow().value.is_none()
                        } else {
                            panic!("internal leaf node is not a leaf");
                        }
                    } else {
                        true
                    }
                }
                NodeBox::Leaf(ref n) => {
                    // If this is a leaf node, check if the value has been evicted. In this case
                    // treat it as if we need to re-fetch the node.
                    n.value.borrow().value.is_none()
                }
            };

            if refetch {
                drop(ptr);
                self.remove_node(ptr_ref.clone());
            } else {
                self.use_node(ptr_ref.clone());
                return Ok(Some(node.clone()));
            }
        } else {
            if !ptr.clean || ptr.is_null() {
                return Ok(None);
            }
            drop(ptr);
        }

        // Node not available locally, fetch from read syncer.
        self.remote_sync(ctx, ptr_ref.clone(), fetcher)?;

        let ptr = ptr_ref.borrow();
        Ok(ptr.node.clone())
    }

    fn remote_sync<F: ReadSyncFetcher>(
        &mut self,
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        fetcher: F,
    ) -> Fallible<()> {
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
            (ptr, ptr_hash)
        } else if proof.untrusted_root == self.sync_root.hash {
            (self.pending_root.clone(), self.sync_root.hash)
        } else {
            return Err(format_err!(
                "urkel: got proof for unexpected root ({:?})",
                proof.untrusted_root
            ));
        };

        // Verify proof.
        let pv = ProofVerifier;
        let subtree = pv.verify_proof(Context::create_child(&ctx), expected_root, &proof)?;

        // Merge resulting nodes.
        let mut merged_nodes: Vec<NodePtrRef> = Vec::new();
        merge_verified_subtree(dst_ptr, subtree, &mut merged_nodes)?;
        for node_ref in merged_nodes {
            self.commit_merged_node(node_ref);
        }

        Ok(())
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

    fn rollback_node(&mut self, ptr: NodePtrRef, kind: NodeKind) {
        if ptr.borrow().get_cache_extra().is_none() {
            // Node has not yet been committed to cache.
            return;
        }

        self.lru_nodes.remove(ptr.clone());

        match kind {
            NodeKind::Internal => self.internal_node_count -= 1,
            NodeKind::Leaf => self.leaf_node_count -= 1,
            _ => panic!("lru_cache: rollback works only for Internal and Leaf nodes!"),
        };

        ptr.borrow_mut().set_cache_extra(None);
    }
}
