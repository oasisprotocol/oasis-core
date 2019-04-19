use std::{cell::RefCell, rc::Rc};

use failure::Fallible;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::urkel::{marshal::*, tree::*},
};

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
