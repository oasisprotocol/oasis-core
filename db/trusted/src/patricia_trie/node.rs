use bincode;

use ekiden_common::bytes::H256;

use super::nibble::NibbleVec;

/// Pointer to a node in the Patricia tree.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum NodePointer {
    /// No pointer.
    Null,
    /// Pointer to a node.
    Pointer(H256),
    /// Embedded node.
    Embedded(Box<Node>),
}

impl NodePointer {
    /// Return a list of null child pointers.
    pub fn null_children() -> [NodePointer; 16] {
        // Must be done manually because NodePointer is not Copy.
        [
            NodePointer::Null,
            NodePointer::Null,
            NodePointer::Null,
            NodePointer::Null,
            NodePointer::Null,
            NodePointer::Null,
            NodePointer::Null,
            NodePointer::Null,
            NodePointer::Null,
            NodePointer::Null,
            NodePointer::Null,
            NodePointer::Null,
            NodePointer::Null,
            NodePointer::Null,
            NodePointer::Null,
            NodePointer::Null,
        ]
    }
}

/// Patricia tree node.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Node {
    /// Branch node.
    Branch {
        ///  16 child pointers (may be NULL).
        children: [NodePointer; 16],
        /// Optional value if this node is also a key.
        value: Option<Vec<u8>>,
    },
    /// Leaf node skipping over a path.
    Leaf {
        /// Path to skip over.
        path: NibbleVec,
        /// Value.
        value: Vec<u8>,
    },
    /// Extension node skipping over a path.
    Extension {
        /// Path to skip over.
        path: NibbleVec,
        /// Node pointer.
        pointer: NodePointer,
    },
}

impl Node {
    /// Maximum size of a node for it to be embedded.
    const MAX_EMBED_SIZE: usize = 32;

    /// Size of serialized node.
    pub fn size(&self) -> usize {
        bincode::serialize(self).unwrap().len()
    }

    /// Check if node can be embedded instead of requiring a pointer.
    pub fn is_embeddable(&self) -> bool {
        self.size() < Node::MAX_EMBED_SIZE
    }
}
