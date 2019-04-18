use std::{cell::RefCell, rc::Rc};

use failure::Fallible;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{cache::*, marshal::*, tree::*},
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
pub struct NodeID {
    pub path: Hash,
    pub depth: u8,
}

impl NodeID {
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

impl Marshal for NodeBox {
    fn marshal_binary(&self) -> Fallible<Vec<u8>> {
        match self {
            NodeBox::Internal(ref n) => n.marshal_binary(),
            NodeBox::Leaf(ref n) => n.marshal_binary(),
        }
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize> {
        if data.len() < 1 {
            Err(TreeError::MalformedNode.into())
        } else {
            let mut kind = NodeKind::None;
            kind.unmarshal_binary(data)?;
            match kind {
                NodeKind::Internal => {
                    *self = NodeBox::Internal(InternalNode {
                        ..Default::default()
                    });
                }
                NodeKind::Leaf => {
                    *self = NodeBox::Leaf(LeafNode {
                        ..Default::default()
                    });
                }
                _ => {
                    return Err(TreeError::MalformedNode.into());
                }
            };
            match self {
                NodeBox::Internal(ref mut n) => n.unmarshal_binary(data),
                NodeBox::Leaf(ref mut n) => n.unmarshal_binary(data),
            }
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

impl Marshal for NodeKind {
    fn marshal_binary(&self) -> Fallible<Vec<u8>> {
        Ok(vec![*self as u8])
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize> {
        if data.len() < 1 {
            Err(TreeError::MalformedNode.into())
        } else {
            if data[0] == NodeKind::None as u8 {
                *self = NodeKind::None;
            } else if data[0] == NodeKind::Internal as u8 {
                *self = NodeKind::Internal;
            } else if data[0] == NodeKind::Leaf as u8 {
                *self = NodeKind::Leaf;
            } else {
                return Err(TreeError::MalformedNode.into());
            }
            Ok(1)
        }
    }
}

/// `NodeRef` is a reference-counted pointer to a node box.
pub type NodeRef = Rc<RefCell<NodeBox>>;

/// A pointer to a node in the tree.
#[derive(Debug, Default)]
pub struct NodePointer {
    pub clean: bool,
    pub hash: Hash,
    pub node: Option<NodeRef>,

    pub cache_extra: u64,
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
}

impl CacheItem for NodePointer {
    fn get_cache_extra(&self) -> u64 {
        self.cache_extra
    }

    fn set_cache_extra(&mut self, new_val: u64) {
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
        let hash_left = self.left.borrow().hash;
        let hash_right = self.right.borrow().hash;
        self.hash = Hash::digest_bytes_list(&[
            &[NodeKind::Internal as u8],
            hash_left.as_ref(),
            hash_right.as_ref(),
        ]);
    }

    fn validate(&mut self, h: Hash) -> Fallible<()> {
        if !self.left.borrow().clean || !self.right.borrow().clean {
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
            left: self.left.borrow().extract(),
            right: self.right.borrow().extract(),
        })))
    }
}

impl Marshal for InternalNode {
    fn marshal_binary(&self) -> Fallible<Vec<u8>> {
        let mut result: Vec<u8> = Vec::with_capacity(1 + 2 * Hash::len());
        result.push(NodeKind::Internal as u8);
        result.extend_from_slice(self.left.borrow().hash.as_ref());
        result.extend_from_slice(self.right.borrow().hash.as_ref());

        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize> {
        if data.len() < 1 + 2 * Hash::len() || data[0] != NodeKind::Internal as u8 {
            return Err(TreeError::MalformedNode.into());
        }

        let left_hash = Hash::from(&data[1..(1 + Hash::len())]);
        let right_hash = Hash::from(&data[(1 + Hash::len())..(1 + 2 * Hash::len())]);

        self.clean = false;
        if left_hash.is_empty() {
            self.left = NodePointer::null_ptr();
        } else {
            self.left = Rc::new(RefCell::new(NodePointer {
                clean: true,
                hash: left_hash,
                node: None,
                ..Default::default()
            }));
        }
        if right_hash.is_empty() {
            self.right = NodePointer::null_ptr();
        } else {
            self.right = Rc::new(RefCell::new(NodePointer {
                clean: true,
                hash: right_hash,
                node: None,
                ..Default::default()
            }));
        }

        Ok(1 + 2 * Hash::len())
    }
}

impl PartialEq for InternalNode {
    fn eq(&self, other: &InternalNode) -> bool {
        if self.clean && other.clean {
            self.hash == other.hash
        } else {
            self.left == other.left && self.right == other.right
        }
    }
}

impl Eq for InternalNode {}

/// A leaf node containing a key/value pair.
#[derive(Debug, Default)]
pub struct LeafNode {
    pub clean: bool,
    pub hash: Hash,
    pub key: Hash,
    pub value: ValuePtrRef,
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
            key: self.key,
            value: self.value.borrow().extract(),
        })))
    }
}

impl Marshal for LeafNode {
    fn marshal_binary(&self) -> Fallible<Vec<u8>> {
        let mut result: Vec<u8> = Vec::with_capacity(1 + 2 * Hash::len());
        result.push(NodeKind::Leaf as u8);
        result.extend_from_slice(self.key.as_ref());
        result.append(&mut self.value.borrow().marshal_binary()?);

        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize> {
        if data.len() < 1 + Hash::len() || data[0] != NodeKind::Leaf as u8 {
            return Err(TreeError::MalformedNode.into());
        }

        self.clean = false;
        self.key = Hash::from(&data[1..(1 + Hash::len())]);
        self.value = Rc::new(RefCell::new(ValuePointer {
            ..Default::default()
        }));
        let value_len = self
            .value
            .borrow_mut()
            .unmarshal_binary(&data[(1 + Hash::len())..])?;

        Ok(1 + Hash::len() + value_len)
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

pub type Value = Vec<u8>;
/// A reference-counted value pointer.
pub type ValuePtrRef = Rc<RefCell<ValuePointer>>;

/// A value pointer holds a value.
#[derive(Debug, Default)]
pub struct ValuePointer {
    pub clean: bool,
    pub hash: Hash,
    pub value: Option<Value>,

    pub cache_extra: u64,
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
}

impl Marshal for ValuePointer {
    fn marshal_binary(&self) -> Fallible<Vec<u8>> {
        let mut result: Vec<u8> = Vec::new();
        let value_len = match self.value {
            None => 0,
            Some(ref v) => v.len(),
        };
        result.append(&mut (value_len as u32).marshal_binary()?);
        if let Some(ref v) = self.value {
            result.extend_from_slice(v.as_ref());
        }
        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize> {
        if data.len() < 4 {
            return Err(TreeError::MalformedNode.into());
        }

        let mut value_len = 0u32;
        value_len.unmarshal_binary(data)?;
        let value_len = value_len as usize;

        if data.len() < 4 + value_len {
            return Err(TreeError::MalformedNode.into());
        }

        self.clean = false;
        self.hash = Hash::default();
        if value_len == 0 {
            self.value = None;
        } else {
            self.value = Some(data[4..(4 + value_len)].to_vec());
        }
        Ok(4 + value_len)
    }
}

impl CacheItem for ValuePointer {
    fn get_cache_extra(&self) -> u64 {
        self.cache_extra
    }

    fn set_cache_extra(&mut self, new_val: u64) {
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

#[macro_export]
macro_rules! classify_noderef {
    (? $e:expr) => {{
        let kind = match $e {
            None => NodeKind::None,
            Some(ref node) => classify_noderef!(node),
        };
        kind
    }};
    ($e:expr) => {{
        // Ensure references don't leak outside this macro.
        let kind = match *$e.borrow() {
            NodeBox::Internal(_) => NodeKind::Internal,
            NodeBox::Leaf(_) => NodeKind::Leaf,
        };
        kind
    }};
}

#[macro_export]
macro_rules! noderef_as {
    ($ref:expr, $type:ident) => {
        match *$ref.borrow() {
            NodeBox::$type(ref deref) => deref,
            _ => unreachable!(),
        }
    };
}

#[macro_export]
macro_rules! noderef_as_mut {
    ($ref:expr, $type:ident) => {
        match *$ref.borrow_mut() {
            NodeBox::$type(ref mut deref) => deref,
            _ => unreachable!(),
        }
    };
}
