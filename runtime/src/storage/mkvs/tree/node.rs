use std::{cell::RefCell, rc::Rc};

use serde::{Deserialize, Serialize};
use serde_repr::*;

use crate::{
    common::{crypto::hash::Hash, namespace::Namespace},
    storage::mkvs::{cache::*, marshal::*},
};

/// Common interface for node-like objects in the tree.
pub trait Node {
    /// Check whether the node is clean or not.
    fn is_clean(&self) -> bool;
    /// Get the node's hash.
    fn get_hash(&self) -> Hash;
    /// Recompute the node's hash.
    fn update_hash(&mut self);
    /// Duplicate the node but include only hash references.
    fn extract(&self) -> NodeRef;
}

/// Storage root type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum RootType {
    /// Invalid or uninitialized storage root type.
    Invalid = 0,
    /// Storage root for runtime state.
    State = 1,
    /// Storage root for transaction IO.
    IO = 2,
}

impl Default for RootType {
    fn default() -> Self {
        RootType::Invalid
    }
}

/// Storage root.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Root {
    /// Namespace under which the root is stored.
    #[serde(rename = "ns")]
    pub namespace: Namespace,
    /// Monotonically increasing version number in which the root is stored.
    pub version: u64,
    /// The storage type that this root has data for.
    pub root_type: RootType,
    /// Merkle root hash.
    pub hash: Hash,
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
            clean: true,
            hash: Hash::empty_hash(),
            ..Default::default()
        }))
    }

    /// Construct a hash-only pointer.
    pub fn hash_ptr(hash: Hash) -> NodePtrRef {
        Rc::new(RefCell::new(NodePointer {
            node: None,
            clean: true,
            hash: hash,
            ..Default::default()
        }))
    }

    /// Construct a node pointer from a full node.
    pub fn from_node(node: NodeBox) -> NodePtrRef {
        Rc::new(RefCell::new(NodePointer {
            hash: node.get_hash(),
            node: Some(Rc::new(RefCell::new(node))),
            clean: true,
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
            None => panic!("mkvs: get_node called on pointer without a node"),
            Some(node) => node.clone(),
        }
    }

    /// Return a copy of this pointer containing only hash references.
    pub fn extract(&self) -> NodePtrRef {
        if !self.clean {
            panic!("mkvs: extract called on dirty pointer");
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
            return NodePointer::null_ptr();
        }

        if !self.clean {
            panic!("mkvs: copy_leaf_ptr called on dirty pointer");
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
            panic!("mkvs: copy_leaf_ptr called on a non-leaf pointer");
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

/// An internal tree node with two children and possibly a leaf.
#[derive(Debug, Default)]
pub struct InternalNode {
    pub clean: bool,
    pub version: u64,
    pub hash: Hash,
    pub label: Key,              // label on the incoming edge
    pub label_bit_length: Depth, // length of the label in bits
    pub leaf_node: NodePtrRef,   // for the key ending at this depth
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
        let leaf_node_hash = self.leaf_node.borrow().hash;
        let left_hash = self.left.borrow().hash;
        let right_hash = self.right.borrow().hash;

        self.hash = Hash::digest_bytes_list(&[
            &[NodeKind::Internal as u8],
            &self.version.marshal_binary().unwrap(),
            &self.label_bit_length.marshal_binary().unwrap(),
            self.label.as_ref(),
            leaf_node_hash.as_ref(),
            left_hash.as_ref(),
            right_hash.as_ref(),
        ]);
    }

    fn extract(&self) -> NodeRef {
        if !self.clean {
            panic!("mkvs: extract called on dirty node");
        }
        Rc::new(RefCell::new(NodeBox::Internal(InternalNode {
            clean: true,
            version: self.version,
            hash: self.hash,
            label: self.label.clone(),
            label_bit_length: self.label_bit_length,
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
            self.version == other.version
                && self.leaf_node == other.leaf_node
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
    pub version: u64,
    pub hash: Hash,
    pub key: Key,
    pub value: Value,
}

impl LeafNode {
    pub fn copy(&self) -> LeafNode {
        let node = LeafNode {
            clean: self.clean,
            version: self.version,
            hash: self.hash.clone(),
            key: self.key.to_owned(),
            value: self.value.clone(),
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
            &self.version.marshal_binary().unwrap(),
            self.key.as_ref(),
            self.value.as_ref(),
        ]);
    }

    fn extract(&self) -> NodeRef {
        if !self.clean {
            panic!("mkvs: extract called on dirty node");
        }
        Rc::new(RefCell::new(NodeBox::Leaf(LeafNode {
            clean: true,
            version: self.version,
            hash: self.hash,
            key: self.key.clone(),
            value: self.value.clone(),
        })))
    }
}

impl PartialEq for LeafNode {
    fn eq(&self, other: &LeafNode) -> bool {
        if self.clean && other.clean {
            self.hash == other.hash
        } else {
            self.version == other.version && self.key == other.key && self.value == other.value
        }
    }
}

impl Eq for LeafNode {}

// Depth determines the maximum length of the key in bits.
//
// max length = 2^size_of(Depth)*8
pub type Depth = u16;

pub trait DepthTrait {
    // Returns the number of bytes needed to fit given bits.
    fn to_bytes(&self) -> usize;
}

impl DepthTrait for Depth {
    fn to_bytes(&self) -> usize {
        let size = self / 8;
        if self % 8 != 0 {
            (size + 1) as usize
        } else {
            size as usize
        }
    }
}

// Key holds variable-length key.
pub type Key = Vec<u8>;

pub trait KeyTrait {
    /// Get a single bit from the given hash.
    fn get_bit(&self, bit: Depth) -> bool;
    /// Set a single bit in the given hash and return the result. If bit>self, it resizes new Key.
    fn set_bit(&self, bit: Depth, val: bool) -> Key;
    /// Returns the length of the key in bits.
    fn bit_length(&self) -> Depth;
    /// Bit-wise splits of the key.
    fn split(&self, split_point: Depth, key_len: Depth) -> (Key, Key);
    /// Bit-wise merges key of given length with another key of given length.
    fn merge(&self, key_len: Depth, k2: &Key, k2_len: Depth) -> Key;
    /// Appends the given bit to the key.
    fn append_bit(&self, key_len: Depth, bit: bool) -> Key;
    /// Computes length of common prefix of k and k2 with given bit lengths.
    fn common_prefix_len(&self, key_len: Depth, k2: &Key, k2_len: Depth) -> Depth;
}

impl KeyTrait for Key {
    fn get_bit(&self, bit: Depth) -> bool {
        (self[(bit / 8) as usize] & (1 << (7 - (bit % 8)))) != 0
    }

    fn set_bit(&self, bit: Depth, val: bool) -> Key {
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

    fn bit_length(&self) -> Depth {
        (self.len() * 8) as Depth
    }

    fn split(&self, split_point: Depth, key_len: Depth) -> (Key, Key) {
        if split_point > key_len {
            panic!(
                "mkvs: split_point {} greater than key_len {}",
                split_point, key_len
            );
        }

        let prefix_len = split_point.to_bytes();
        let suffix_len = (key_len - split_point).to_bytes();
        let mut prefix: Key = vec![0; prefix_len];
        let mut suffix: Key = vec![0; suffix_len];

        prefix.clone_from_slice(&self[0..split_point.to_bytes()]);

        // Clean the remainder of the byte.
        if split_point % 8 != 0 {
            prefix[prefix_len - 1] &= 0xff << (8 - split_point % 8)
        }

        for i in 0..suffix_len {
            // First set the left chunk of the byte
            suffix[i] = self[i + split_point as usize / 8] << (split_point % 8);
            // ...and the right chunk, if we haven't reached the end of k yet.
            if split_point % 8 != 0 && i + split_point as usize / 8 + 1 != self.len() {
                suffix[i] |=
                    self[i + split_point as usize / 8 + 1] >> (8 - split_point as usize % 8);
            }
        }

        (prefix, suffix)
    }

    fn merge(&self, key_len: Depth, k2: &Key, k2_len: Depth) -> Key {
        let mut key_len_bytes = (key_len as usize) / 8;
        if key_len % 8 != 0 {
            key_len_bytes += 1;
        }

        let mut new_key: Key = vec![0; (key_len + k2_len).to_bytes()];
        new_key[..key_len_bytes].clone_from_slice(&self[..key_len_bytes]);

        for i in 0..k2.len() as usize {
            // First set the right chunk of the previous byte
            if key_len % 8 != 0 && key_len_bytes > 0 {
                new_key[key_len_bytes + i - 1] |= k2[i] >> (key_len % 8);
            }
            // ...and the next left chunk, if we haven't reached the end of newKey
            // yet.
            if key_len_bytes + i < new_key.len() {
                // another mod 8 to prevent bit shifting for 8 bits
                new_key[key_len_bytes + i] |= k2[i] << ((8 - key_len % 8) % 8);
            }
        }

        new_key
    }

    fn append_bit(&self, key_len: Depth, val: bool) -> Key {
        let mut new_key: Key = vec![0; (key_len + 1).to_bytes()];
        new_key[..self.len()].clone_from_slice(self);

        if val {
            new_key[key_len as usize / 8] |= 0x80 >> (key_len % 8)
        } else {
            new_key[key_len as usize / 8] &= !(0x80 >> (key_len % 8))
        }

        new_key
    }

    fn common_prefix_len(&self, key_bit_len: Depth, k2: &Key, k2_bit_len: Depth) -> Depth {
        let min_key_len = if k2.len() < self.len() {
            k2.len()
        } else {
            self.len()
        };

        // Compute the common prefix byte-wise.
        let mut i: usize = 0;
        while i < min_key_len {
            if self[i] != k2[i] {
                break;
            }
            i += 1;
        }

        // Prefixes match i bytes and maybe some more bits below.
        let mut bit_length = (i * 8) as Depth;

        if i != self.len() && i != k2.len() {
            // We got a mismatch somewhere along the way. We need to compute how
            // many additional bits in i-th byte match.
            bit_length += (self[i] ^ k2[i]).leading_zeros() as Depth;
        }

        // In any case, bit_length should never exceed length of the shorter key.
        if bit_length > key_bit_len {
            bit_length = key_bit_len;
        }
        if bit_length > k2_bit_len {
            bit_length = k2_bit_len;
        };
        bit_length
    }
}

// Value holds the leaf node value.
pub type Value = Vec<u8>;
