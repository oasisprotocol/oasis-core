use std::{cell::RefCell, mem::size_of, rc::Rc};

use anyhow::Result;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::{marshal::*, tree::*},
};

/// Size of the encoded value length.
const VALUE_LENGTH_SIZE: usize = size_of::<u32>();

impl Marshal for NodeBox {
    fn marshal_binary(&self) -> Result<Vec<u8>> {
        match self {
            NodeBox::Internal(ref n) => n.marshal_binary(),
            NodeBox::Leaf(ref n) => n.marshal_binary(),
        }
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
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
    fn marshal_binary(&self) -> Result<Vec<u8>> {
        Ok(vec![*self as u8])
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
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
    fn marshal_binary(&self) -> Result<Vec<u8>> {
        let leaf_node_binary = if self.leaf_node.borrow().is_null() {
            vec![NodeKind::None as u8]
        } else {
            noderef_as!(self.leaf_node.borrow().get_node(), Leaf).marshal_binary()?
        };

        let mut result: Vec<u8> = Vec::with_capacity(1 + leaf_node_binary.len() + 2 * Hash::len());
        result.push(NodeKind::Internal as u8);
        result.append(&mut self.label_bit_length.marshal_binary()?);
        result.extend_from_slice(&self.label);
        result.extend_from_slice(leaf_node_binary.as_ref());
        result.extend_from_slice(self.left.borrow().hash.as_ref());
        result.extend_from_slice(self.right.borrow().hash.as_ref());

        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<usize> {
        let mut pos = 0;
        if data.len() < 1 + size_of::<Depth>() + 1 || data[pos] != NodeKind::Internal as u8 {
            return Err(TreeError::MalformedNode.into());
        }
        pos += 1;

        pos += self.label_bit_length.unmarshal_binary(&data[pos..])?;
        self.label = vec![0; self.label_bit_length.to_bytes()];
        if pos + self.label_bit_length.to_bytes() > data.len() {
            return Err(TreeError::MalformedNode.into());
        }
        self.label
            .clone_from_slice(&data[pos..pos + self.label_bit_length.to_bytes()]);
        pos += self.label_bit_length.to_bytes();
        if pos >= data.len() {
            return Err(TreeError::MalformedNode.into());
        }

        if data[pos] == NodeKind::None as u8 {
            self.leaf_node = NodePointer::null_ptr();
            pos += 1;
        } else {
            let mut leaf_node = LeafNode {
                ..Default::default()
            };
            pos += leaf_node.unmarshal_binary(&data[pos..])?;
            self.leaf_node = Rc::new(RefCell::new(NodePointer {
                clean: true,
                hash: leaf_node.get_hash(),
                node: Some(Rc::new(RefCell::new(NodeBox::Leaf(leaf_node)))),
                ..Default::default()
            }));
        };

        // Hashes are only present in non-compact serialization.
        if data.len() >= pos + Hash::len() * 2 {
            let left_hash = Hash::from(&data[pos..pos + Hash::len()]);
            pos += Hash::len();
            let right_hash = Hash::from(&data[pos..pos + Hash::len()]);
            pos += Hash::len();

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
        }

        self.clean = true;

        Ok(pos)
    }
}

impl Marshal for LeafNode {
    fn marshal_binary(&self) -> Result<Vec<u8>> {
        let mut result: Vec<u8> = Vec::with_capacity(1 + VALUE_LENGTH_SIZE);
        result.push(NodeKind::Leaf as u8);
        result.append(&mut self.key.marshal_binary()?);
        result.append(&mut (self.value.len() as u32).marshal_binary()?);
        result.extend_from_slice(&self.value);

        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 1 + size_of::<Depth>() + VALUE_LENGTH_SIZE
            || data[0] != NodeKind::Leaf as u8
        {
            return Err(TreeError::MalformedNode.into());
        }

        self.clean = true;

        let mut pos = 1;
        self.key = Key::new();
        let key_len = self.key.unmarshal_binary(&data[pos..])?;
        pos += key_len;
        if pos + VALUE_LENGTH_SIZE > data.len() {
            return Err(TreeError::MalformedNode.into());
        }

        self.value = Value::new();
        let mut value_len = 0u32;
        value_len.unmarshal_binary(&data[pos..(pos + VALUE_LENGTH_SIZE)])?;
        pos += VALUE_LENGTH_SIZE;
        if pos + (value_len as usize) > data.len() {
            return Err(TreeError::MalformedNode.into());
        }

        self.value
            .extend_from_slice(&data[pos..(pos + value_len as usize)]);
        pos += value_len as usize;

        self.update_hash();

        Ok(pos)
    }
}

impl Marshal for Key {
    fn marshal_binary(&self) -> Result<Vec<u8>> {
        let mut result: Vec<u8> = Vec::new();
        result.append(&mut (self.len() as Depth).marshal_binary()?);
        result.extend_from_slice(self);
        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < size_of::<Depth>() {
            return Err(TreeError::MalformedKey.into());
        }
        let mut key_len: Depth = 0;
        key_len.unmarshal_binary(data)?;

        if data.len() < size_of::<Depth>() + key_len as usize {
            return Err(TreeError::MalformedKey.into());
        }

        self.extend_from_slice(&data[size_of::<Depth>()..(size_of::<Depth>() + key_len as usize)]);
        Ok(size_of::<Depth>() + key_len as usize)
    }
}
