use std::{cell::RefCell, io::Cursor, rc::Rc};

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

impl Marshal for SubtreeIndex {
    fn marshal_binary(&self) -> Fallible<Vec<u8>> {
        let mut result: Vec<u8> = Vec::with_capacity(2);
        result.write_u16::<LittleEndian>(*self)?;
        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize> {
        if data.len() < 2 {
            Err(SubtreeError::Malformed.into())
        } else {
            let mut reader = Cursor::new(data);
            *self = reader.read_u16::<LittleEndian>()?;
            Ok(2)
        }
    }
}

impl Marshal for SubtreePointer {
    fn marshal_binary(&self) -> Fallible<Vec<u8>> {
        let mut result: Vec<u8> = Vec::with_capacity(4);
        result.append(&mut self.index.marshal_binary()?);
        result.push(if self.full { 1u8 } else { 0u8 });
        result.push(if self.valid { 1u8 } else { 0u8 });
        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize> {
        if data.len() < 4 {
            Err(SubtreeError::Malformed.into())
        } else {
            self.index.unmarshal_binary(&data[0..2])?;
            self.full = data[2] > 0;
            self.valid = data[3] > 0;
            Ok(4)
        }
    }
}

impl Marshal for InternalNodeSummary {
    fn marshal_binary(&self) -> Fallible<Vec<u8>> {
        let mut result: Vec<u8> = Vec::with_capacity(9);
        result.push(if self.invalid { 1u8 } else { 0u8 });
        result.append(&mut self.left.marshal_binary()?);
        result.append(&mut self.right.marshal_binary()?);
        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize> {
        if data.len() < 9 {
            Err(SubtreeError::Malformed.into())
        } else {
            self.invalid = data[0] > 0;
            self.left.unmarshal_binary(&data[1..5])?;
            self.right.unmarshal_binary(&data[5..])?;
            Ok(9)
        }
    }
}

impl Marshal for Subtree {
    fn marshal_binary(&self) -> Fallible<Vec<u8>> {
        let mut result: Vec<u8> = Vec::new();
        result.push(SUBTREE_PREFIX);
        result.append(&mut self.root.marshal_binary()?);

        // Summaries.
        result.append(&mut (self.summaries.len() as u64).marshal_binary()?);
        for summary in &self.summaries {
            result.append(&mut summary.marshal_binary()?);
        }

        // Full nodes.
        result.append(&mut (self.full_nodes.len() as u64).marshal_binary()?);
        for node in &self.full_nodes {
            match node {
                None => result.append(&mut 0u64.marshal_binary()?),
                Some(node) => {
                    let mut data = node.borrow().marshal_binary()?;
                    result.append(&mut (data.len() as u64).marshal_binary()?);
                    result.append(&mut data)
                }
            };
        }

        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize> {
        if data.len() < 21 || data[0] != SUBTREE_PREFIX {
            Err(SubtreeError::Malformed.into())
        } else {
            let mut offset = 1 + self.root.unmarshal_binary(&data[1..])?;

            // Summaries.
            let mut summaries_len: u64 = 0;
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
            let mut nodes_len: u64 = 0;
            self.full_nodes.clear();
            offset += nodes_len.unmarshal_binary(&data[offset..])?;
            for _ in 0..nodes_len {
                let mut item_len: u64 = 0;
                offset += item_len.unmarshal_binary(&data[offset..])?;
                if item_len == 0 {
                    self.full_nodes.push(None);
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
