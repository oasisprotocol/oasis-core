use failure::Fallible;

use crate::storage::mkvs::urkel::{sync::*, tree::*};

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
#[derive(Clone, Debug, Default)]
pub struct SubtreePointer {
    pub index: SubtreeIndex,
    pub full: bool,
    pub valid: bool,
}

/// A compressed (index-only) representation of an internal node.
#[derive(Clone, Debug, Default)]
pub struct InternalNodeSummary {
    pub invalid: bool,

    pub left: SubtreePointer,
    pub right: SubtreePointer,
}

/// A compressed representation of a subtree.
#[derive(Debug, Default)]
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
