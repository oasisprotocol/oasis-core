use std::{cell::RefCell, rc::Rc};

use failure::Fallible;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{cache::*, tree::*},
};

/// Common interface for node-like objects in the tree.
pub trait Node {
    /// Check whether the node is clean or not.
    fn is_clean(&self) -> bool;
    /// Get the node's hash.
    fn get_hash(&self) -> Hash;
    /// Recompute the node's hash.
    fn update_hash(&mut self);
    /// Check if the node's hash matches its contents.
    fn validate(&mut self, h: Hash) -> Fallible<()>;
    /// Duplicate the node but include only hash references.
    fn extract(&self) -> NodeRef;
}

/// `NodeID` is a root-relative identifier which uniquely identifies a node
/// under a given root.
#[derive(Clone, Copy, Debug)]
pub struct NodeID<'a> {
    pub path: &'a Key,
    pub depth: u8,
}

impl<'a> NodeID<'a> {
    /// Return a copy of this `NodeID` with a different depth.
    pub fn at_depth(&self, depth: u8) -> NodeID {
        NodeID {
            path: self.path,
            depth: depth,
        }
    }
}

/// A box type that can contain either internal or leaf nodes.
#[derive(Debug, Eq, PartialEq)]
pub enum NodeBox {
    Internal(InternalNode),
    Leaf(LeafNode),
}

impl Default for NodeBox {
    fn default() -> Self {
        NodeBox::Internal(Default::default())
    }
}

impl Node for NodeBox {
    fn is_clean(&self) -> bool {
        match self {
            NodeBox::Internal(ref n) => n.is_clean(),
            NodeBox::Leaf(ref n) => n.is_clean(),
        }
    }

    fn get_hash(&self) -> Hash {
        match self {
            NodeBox::Internal(ref n) => n.get_hash(),
            NodeBox::Leaf(ref n) => n.get_hash(),
        }
    }

    fn update_hash(&mut self) {
        match self {
            NodeBox::Internal(ref mut n) => n.update_hash(),
            NodeBox::Leaf(ref mut n) => n.update_hash(),
        }
    }

    fn validate(&mut self, h: Hash) -> Fallible<()> {
        match self {
            NodeBox::Internal(ref mut n) => n.validate(h),
            NodeBox::Leaf(ref mut n) => n.validate(h),
        }
    }

    fn extract(&self) -> NodeRef {
        match self {
            NodeBox::Internal(ref n) => n.extract(),
            NodeBox::Leaf(ref n) => n.extract(),
        }
    }
}

/// Node types in the tree.
///
/// Integer values of the variants here are also used in subtree
/// serialization and as prefixes in node hash computations.
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum NodeKind {
    None = 0x02,
    Internal = 0x01,
    Leaf = 0x00,
}

/// `NodeRef` is a reference-counted pointer to a node box.
pub type NodeRef = Rc<RefCell<NodeBox>>;

/// A pointer to a node in the tree.
#[derive(Debug, Default)]
pub struct NodePointer {
    pub clean: bool,
    pub hash: Hash,
    pub node: Option<NodeRef>,

    pub cache_extra: CacheExtra<NodePointer>,
}

/// A reference-counted pointer to a pointer.
pub type NodePtrRef = Rc<RefCell<NodePointer>>;

impl NodePointer {
    /// Construct a null pointer.
    pub fn null_ptr() -> NodePtrRef {
        Rc::new(RefCell::new(NodePointer {
            node: None,
            hash: Hash::empty_hash(),
            ..Default::default()
        }))
    }

    /// Check if the pointer is a null pointer.
    pub fn is_null(&self) -> bool {
        self.hash.is_empty()
    }

    /// Check if the pointer has a resolved reference to a concrete node.
    pub fn has_node(&self) -> bool {
        !self.is_null() && !self.node.is_none()
    }

    /// Get a reference to the node the pointer is pointing to.
    pub fn get_node(&self) -> NodeRef {
        match &self.node {
            None => panic!("urkel: get_node called on pointer without a node"),
            Some(node) => node.clone(),
        }
    }

    /// Return a copy of this pointer containing only hash references.
    pub fn extract(&self) -> NodePtrRef {
        if !self.clean {
            panic!("urkel: extract called on dirty pointer");
        }
        Rc::new(RefCell::new(NodePointer {
            clean: true,
            hash: self.hash,
            ..Default::default()
        }))
    }

    // Make deep copy of the Pointer to LeafNode excluding LRU and DBInternal.
    //
    // Panics, if it's called on non-leaf node pointer.
    fn copy_leaf_ptr(&self) -> NodePtrRef {
        if !self.has_node() {
            return Rc::new(RefCell::new(NodePointer {
                node: None,
                hash: Hash::empty_hash(),
                ..Default::default()
            }));
        }

        if !self.clean {
            panic!("urkel: copy_leaf_ptr called on dirty pointer");
        }
        if let Some(ref some_node) = self.node {
            let nyoo = noderef_as!(some_node, Leaf).copy();
            Rc::new(RefCell::new(NodePointer {
                clean: true,
                hash: self.hash,
                node: Some(Rc::new(RefCell::new(NodeBox::Leaf(nyoo)))),
                ..Default::default()
            }))
        } else {
            panic!("urkel: copy_leaf_ptr called on a non-leaf pointer");
        }
    }
}

impl CacheItem for NodePointer {
    fn get_cache_extra(&self) -> CacheExtra<NodePointer> {
        self.cache_extra
    }

    fn set_cache_extra(&mut self, new_val: CacheExtra<NodePointer>) {
        self.cache_extra = new_val;
    }

    fn get_cached_size(&self) -> usize {
        1
    }
}

impl PartialEq for NodePointer {
    fn eq(&self, other: &NodePointer) -> bool {
        if self.clean && other.clean {
            self.hash == other.hash
        } else {
            self.node != None && self.node == other.node
        }
    }
}

impl Eq for NodePointer {}

/// An internal tree node with two children.
#[derive(Debug, Default)]
pub struct InternalNode {
    pub clean: bool,
    pub hash: Hash,
    pub leaf_node: NodePtrRef,
    pub left: NodePtrRef,
    pub right: NodePtrRef,
}

impl Node for InternalNode {
    fn is_clean(&self) -> bool {
        self.clean
    }

    fn get_hash(&self) -> Hash {
        self.hash
    }

    fn update_hash(&mut self) {
        let hash_leaf_node = self.leaf_node.borrow().hash;
        let hash_left = self.left.borrow().hash;
        let hash_right = self.right.borrow().hash;
        self.hash = Hash::digest_bytes_list(&[
            &[NodeKind::Internal as u8],
            hash_leaf_node.as_ref(),
            hash_left.as_ref(),
            hash_right.as_ref(),
        ]);
    }

    fn validate(&mut self, h: Hash) -> Fallible<()> {
        if !self.leaf_node.borrow().clean || !self.left.borrow().clean || !self.right.borrow().clean
        {
            Err(TreeError::DirtyPointers.into())
        } else {
            self.update_hash();

            if self.hash != h {
                Err(TreeError::HashMismatch {
                    expected_hash: h,
                    computed_hash: self.hash,
                }
                .into())
            } else {
                Ok(())
            }
        }
    }

    fn extract(&self) -> NodeRef {
        if !self.clean {
            panic!("urkel: extract called on dirty node");
        }
        Rc::new(RefCell::new(NodeBox::Internal(InternalNode {
            clean: true,
            hash: self.hash,
            leaf_node: self.leaf_node.borrow().copy_leaf_ptr(),
            left: self.left.borrow().extract(),
            right: self.right.borrow().extract(),
        })))
    }
}

impl PartialEq for InternalNode {
    fn eq(&self, other: &InternalNode) -> bool {
        if self.clean && other.clean {
            self.hash == other.hash
        } else {
            self.leaf_node == other.leaf_node
                && self.left == other.left
                && self.right == other.right
        }
    }
}

impl Eq for InternalNode {}

/// A leaf node containing a key/value pair.
#[derive(Debug, Default)]
pub struct LeafNode {
    pub clean: bool,
    pub hash: Hash,
    pub key: Key,
    pub value: ValuePtrRef,
}

impl LeafNode {
    pub fn copy(&self) -> LeafNode {
        let node = LeafNode {
            clean: self.clean,
            hash: self.hash.clone(),
            key: self.key.to_owned(),
            value: self.value.borrow().copy(),
        };

        return node;
    }
}

impl Node for LeafNode {
    fn is_clean(&self) -> bool {
        self.clean
    }

    fn get_hash(&self) -> Hash {
        self.hash
    }

    fn update_hash(&mut self) {
        self.hash = Hash::digest_bytes_list(&[
            &[NodeKind::Leaf as u8],
            self.key.as_ref(),
            self.value.borrow().hash.as_ref(),
        ]);
    }

    fn validate(&mut self, h: Hash) -> Fallible<()> {
        if !self.value.borrow().clean {
            Err(TreeError::DirtyValue.into())
        } else {
            self.update_hash();

            if self.hash != h {
                Err(TreeError::HashMismatch {
                    expected_hash: h,
                    computed_hash: self.hash,
                }
                .into())
            } else {
                Ok(())
            }
        }
    }

    fn extract(&self) -> NodeRef {
        if !self.clean {
            panic!("urkel: extract called on dirty node");
        }
        Rc::new(RefCell::new(NodeBox::Leaf(LeafNode {
            clean: true,
            hash: self.hash,
            key: self.key.clone(),
            value: self.value.borrow().extract(),
        })))
    }
}

impl PartialEq for LeafNode {
    fn eq(&self, other: &LeafNode) -> bool {
        if self.clean && other.clean {
            self.hash == other.hash
        } else {
            self.key == other.key && self.value == other.value
        }
    }
}

impl Eq for LeafNode {}

pub type Key = Vec<u8>;

pub trait KeyTrait {
    /// Get a single bit from the given hash.
    fn get_bit(&self, bit: u8) -> bool;
    /// Set a single bit in the given hash and return the result. If bit>self, it resizes new Key.
    fn set_bit(&self, bit: u8, val: bool) -> Key;
    /// Returns the length of the key in bits.
    fn bit_length(&self) -> u8;
}

impl KeyTrait for Key {
    fn get_bit(&self, bit: u8) -> bool {
        (self[(bit / 8) as usize] & (1 << (7 - (bit % 8)))) != 0
    }

    fn set_bit(&self, bit: u8, val: bool) -> Key {
        let mut k: Key;
        if bit as usize >= self.len() * 8 {
            k = vec![0; bit as usize / 8 + 1];
            k[0..self.len()].clone_from_slice(&self);
        } else {
            k = self.clone();
        }

        let mask = (1 << (7 - (bit % 8))) as u8;
        if val {
            k[(bit / 8) as usize] |= mask;
        } else {
            k[(bit / 8) as usize] &= !mask;
        }
        k
    }

    fn bit_length(&self) -> u8 {
        self.len() as u8 * 8
    }
}

pub type Value = Vec<u8>;
/// A reference-counted value pointer.
pub type ValuePtrRef = Rc<RefCell<ValuePointer>>;

/// A value pointer holds a value.
#[derive(Debug, Default)]
pub struct ValuePointer {
    pub clean: bool,
    pub hash: Hash,
    pub value: Option<Value>,

    pub cache_extra: CacheExtra<ValuePointer>,
}

impl ValuePointer {
    pub fn update_hash(&mut self) {
        match &self.value {
            None => self.hash = Hash::empty_hash(),
            Some(ref val) => self.hash = Hash::digest_bytes(&val[..]),
        };
    }

    pub fn validate(&mut self, hash: Hash) -> Fallible<()> {
        self.update_hash();
        if self.hash != hash {
            Err(TreeError::HashMismatch {
                expected_hash: hash,
                computed_hash: self.hash,
            }
            .into())
        } else {
            Ok(())
        }
    }

    pub fn extract(&self) -> ValuePtrRef {
        if !self.clean {
            panic!("urkel: extract called on dirty value");
        }
        Rc::new(RefCell::new(ValuePointer {
            clean: true,
            hash: self.hash,
            value: self.value.clone(),
            ..Default::default()
        }))
    }

    // Makes a deep copy of the Value.
    pub fn copy(&self) -> ValuePtrRef {
        Rc::new(RefCell::new(ValuePointer {
            clean: true,
            hash: self.hash.clone(),
            value: self.value.clone().to_owned(),
            ..Default::default()
        }))
    }
}

impl CacheItem for ValuePointer {
    fn get_cache_extra(&self) -> CacheExtra<ValuePointer> {
        self.cache_extra
    }

    fn set_cache_extra(&mut self, new_val: CacheExtra<ValuePointer>) {
        self.cache_extra = new_val;
    }

    fn get_cached_size(&self) -> usize {
        match &self.value {
            None => panic!("urkel: tried to cache None value"),
            Some(ref val) => val.len(),
        }
    }
}

impl PartialEq for ValuePointer {
    fn eq(&self, other: &ValuePointer) -> bool {
        if self.clean && other.clean {
            self.hash == other.hash
        } else {
            self.value != None && self.value == other.value
        }
    }
}

impl Eq for ValuePointer {}
