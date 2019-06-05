use std::{cell::RefCell, mem::size_of, rc::Rc};

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
        let mut result: Vec<u8> = Vec::with_capacity(1 + 3 * Hash::len());
        result.push(NodeKind::Internal as u8);
        result.extend_from_slice(self.leaf_node.borrow().hash.as_ref());
        result.extend_from_slice(self.left.borrow().hash.as_ref());
        result.extend_from_slice(self.right.borrow().hash.as_ref());

        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize> {
        if data.len() < 1 + 3 * Hash::len() || data[0] != NodeKind::Internal as u8 {
            return Err(TreeError::MalformedNode.into());
        }

        let leaf_node_hash = Hash::from(&data[1..(1 + Hash::len())]);
        let left_hash = Hash::from(&data[(1 + Hash::len())..(1 + 2 * Hash::len())]);
        let right_hash = Hash::from(&data[(1 + 2 * Hash::len())..(1 + 3 * Hash::len())]);

        self.clean = true;
        if leaf_node_hash.is_empty() {
            self.leaf_node = NodePointer::null_ptr();
        } else {
            self.leaf_node = Rc::new(RefCell::new(NodePointer {
                clean: true,
                hash: leaf_node_hash,
                node: None,
                ..Default::default()
            }));
        }
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

        self.update_hash();

        Ok(1 + 3 * Hash::len())
    }
}

impl Marshal for LeafNode {
    fn marshal_binary(&self) -> Fallible<Vec<u8>> {
        let mut result: Vec<u8> = Vec::with_capacity(1 + 3 * Hash::len());
        result.push(NodeKind::Leaf as u8);
        result.append(&mut self.key.marshal_binary()?);
        result.append(&mut self.value.borrow().marshal_binary()?);

        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize> {
        if data.len() < 1 + size_of::<DepthType>() || data[0] != NodeKind::Leaf as u8 {
            return Err(TreeError::MalformedNode.into());
        }

        self.clean = true;
        self.key = Key::new();
        let key_len = self.key.unmarshal_binary(&data[1..])?;

        self.value = Rc::new(RefCell::new(ValuePointer {
            ..Default::default()
        }));
        let value_len = self
            .value
            .borrow_mut()
            .unmarshal_binary(&data[(1 + key_len)..])?;

        self.update_hash();

        Ok(1 + key_len + value_len)
    }
}

impl Marshal for Key {
    fn marshal_binary(&self) -> Fallible<Vec<u8>> {
        let mut result: Vec<u8> = Vec::new();
        result.append(&mut (self.len() as DepthType).marshal_binary()?);
        result.extend_from_slice(self);
        Ok(result)
    }
    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize> {
        if data.len() < size_of::<DepthType>() {
            return Err(TreeError::MalformedKey.into());
        }
        let mut key_len: DepthType = 0;
        key_len.unmarshal_binary(data)?;

        if data.len() < size_of::<DepthType>() + key_len as usize {
            return Err(TreeError::MalformedKey.into());
        }

        self.extend_from_slice(
            &data[size_of::<DepthType>()..(size_of::<DepthType>() + key_len as usize)],
        );
        Ok(size_of::<DepthType>() + key_len as usize)
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

        self.clean = true;
        self.hash = Hash::default();
        if value_len == 0 {
            self.value = None;
        } else {
            self.value = Some(data[4..(4 + value_len)].to_vec());
        }
        self.update_hash();
        Ok(4 + value_len)
    }
}
