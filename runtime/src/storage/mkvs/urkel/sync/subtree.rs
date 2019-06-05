use std::{cell::RefCell, io::Cursor, mem::size_of, rc::Rc};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use failure::Fallible;

use crate::storage::mkvs::urkel::{marshal::*, sync::*, tree::*};

/// A subtree index.
pub type SubtreeIndex = u16;

/// Constant used as an invalid subtree index.
const INVALID_SUBTREE_INDEX: SubtreeIndex = 0xffff;

pub trait SubtreeIndexTrait {
    /// Construct an invalid subtree index.
    fn invalid() -> SubtreeIndex;
}

impl SubtreeIndexTrait for SubtreeIndex {
    fn invalid() -> SubtreeIndex {
        INVALID_SUBTREE_INDEX
    }
}

/// A pointer into the compressed representation of a subtree.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SubtreePointer {
    pub index: SubtreeIndex,
    pub full: bool,
    pub valid: bool,
}

/// A compressed (index-only) representation of an internal node.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InternalNodeSummary {
    pub invalid: bool,

    pub leaf_node: SubtreePointer,
    pub left: SubtreePointer,
    pub right: SubtreePointer,
}

/// A compressed representation of a subtree.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Subtree {
    pub root: SubtreePointer,
    summaries: Vec<InternalNodeSummary>,
    full_nodes: Vec<Option<NodeRef>>,
}

impl Subtree {
    /// Construct a new subtree instance.
    pub fn new() -> Subtree {
        Subtree {
            ..Default::default()
        }
    }

    fn check_subtree_index(&self, idx: usize) -> Fallible<SubtreeIndex> {
        if idx >= INVALID_SUBTREE_INDEX as usize {
            Err(SubtreeError::TooManyFullNodes.into())
        } else {
            Ok(idx as SubtreeIndex)
        }
    }

    /// Add a new internal node summary to the subtree.
    pub fn add_summary(&mut self, node: &InternalNodeSummary) -> Fallible<SubtreeIndex> {
        let sidx = self.check_subtree_index(self.summaries.len())?;
        self.summaries.push(node.clone());
        Ok(sidx)
    }

    /// Add a new full node to the subtree.
    pub fn add_full_node(&mut self, node: NodeRef) -> Fallible<SubtreeIndex> {
        let sidx = self.check_subtree_index(self.full_nodes.len())?;
        self.full_nodes.push(Some(node.clone()));
        Ok(sidx)
    }

    /// Retrieve a full node at a specific index.
    ///
    /// If the index has already been marked as used it returns an error.
    pub fn get_full_node_at(&self, idx: SubtreeIndex) -> Fallible<NodeRef> {
        if idx == INVALID_SUBTREE_INDEX || idx as usize >= self.full_nodes.len() {
            Err(SubtreeError::InvalidSubtreeIndex.into())
        } else {
            match self.full_nodes[idx as usize] {
                None => Err(SubtreeError::InvalidSubtreeIndex.into()),
                Some(ref node_ref) => Ok(node_ref.clone()),
            }
        }
    }

    /// Retrieve an internal node summary at a specific index.
    ///
    /// If the index has already been marked as used it returns an error.
    pub fn get_summary_at(&self, idx: SubtreeIndex) -> Fallible<Option<InternalNodeSummary>> {
        if idx == INVALID_SUBTREE_INDEX {
            Ok(None)
        } else if idx as usize >= self.summaries.len() {
            Err(SubtreeError::InvalidSubtreeIndex.into())
        } else {
            let ret = &self.summaries[idx as usize];
            if ret.invalid {
                Err(SubtreeError::InvalidSubtreeIndex.into())
            } else {
                Ok(Some(ret.clone()))
            }
        }
    }

    /// Mark the given index as used.
    pub fn mark_used(&mut self, ptr: SubtreePointer) {
        if ptr.full {
            self.full_nodes[ptr.index as usize] = None;
        } else if ptr.index != INVALID_SUBTREE_INDEX {
            self.summaries[ptr.index as usize].invalid = true;
        }
    }
}

// Size of the subtree pointer: index + flag byte.
const SUBTREE_POINTER_LEN: usize = size_of::<SubtreeIndex>() + 1;
impl Marshal for SubtreePointer {
    fn marshal_binary(&self) -> Fallible<Vec<u8>> {
        let mut result: Vec<u8> = Vec::with_capacity(SUBTREE_POINTER_LEN);
        result.append(&mut self.index.marshal_binary()?);
        result.push(if self.full { 1u8 } else { 0u8 });
        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize> {
        if data.len() < SUBTREE_POINTER_LEN || data[size_of::<SubtreeIndex>()] > 1 {
            Err(SubtreeError::Malformed.into())
        } else {
            self.index
                .unmarshal_binary(&data[0..size_of::<SubtreeIndex>()])?;
            self.full = data[size_of::<SubtreeIndex>()] > 0;
            self.valid = true;
            Ok(3)
        }
    }
}

const SUMMARY_NODE_LEN: usize = 3 * SUBTREE_POINTER_LEN;
impl Marshal for InternalNodeSummary {
    fn marshal_binary(&self) -> Fallible<Vec<u8>> {
        let mut result: Vec<u8> = Vec::with_capacity(SUMMARY_NODE_LEN);
        result.append(&mut self.leaf_node.marshal_binary()?);
        result.append(&mut self.left.marshal_binary()?);
        result.append(&mut self.right.marshal_binary()?);
        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize> {
        if data.len() < SUMMARY_NODE_LEN {
            Err(SubtreeError::Malformed.into())
        } else {
            let mut size = 0usize;
            size += self.leaf_node.unmarshal_binary(&data[size..])?;
            size += self.left.unmarshal_binary(&data[size..])?;
            size += self.right.unmarshal_binary(&data[size..])?;
            self.invalid = false;
            Ok(size)
        }
    }
}

impl Marshal for Subtree {
    fn marshal_binary(&self) -> Fallible<Vec<u8>> {
        let mut result: Vec<u8> = Vec::new();
        result.append(&mut self.root.marshal_binary()?);

        // Summaries.
        result.append(&mut (self.summaries.len() as SubtreeIndex).marshal_binary()?);
        for summary in &self.summaries {
            result.append(&mut summary.marshal_binary()?);
        }

        // Full nodes.
        result.append(&mut (self.full_nodes.len() as SubtreeIndex).marshal_binary()?);
        for node in &self.full_nodes {
            match node {
                None => result.push(NodeKind::None as u8),
                Some(node) => {
                    let mut data = node.borrow().marshal_binary()?;
                    result.append(&mut data)
                }
            };
        }

        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize> {
        if data.len() < SUBTREE_POINTER_LEN + 2 * size_of::<SubtreeIndex>() {
            Err(SubtreeError::Malformed.into())
        } else {
            let mut offset = self.root.unmarshal_binary(data)?;

            // Summaries.
            let mut summaries_len: SubtreeIndex = 0;
            self.summaries.clear();
            offset += summaries_len.unmarshal_binary(&data[offset..])?;
            for _ in 0..summaries_len {
                let mut item = InternalNodeSummary {
                    ..Default::default()
                };
                offset += item.unmarshal_binary(&data[offset..])?;
                self.summaries.push(item);
            }

            // Full nodes.
            let mut nodes_len: SubtreeIndex = 0;
            self.full_nodes.clear();
            offset += nodes_len.unmarshal_binary(&data[offset..])?;
            for _ in 0..nodes_len {
                if data.len() <= offset {
                    return Err(SubtreeError::Malformed.into());
                }
                if data[offset] == NodeKind::None as u8 {
                    self.full_nodes.push(None);
                    offset += 1;
                } else {
                    let mut item = NodeBox::Internal(InternalNode {
                        ..Default::default()
                    });
                    offset += item.unmarshal_binary(&data[offset..])?;
                    self.full_nodes.push(Some(Rc::new(RefCell::new(item))));
                }
            }
            Ok(offset)
        }
    }
}
