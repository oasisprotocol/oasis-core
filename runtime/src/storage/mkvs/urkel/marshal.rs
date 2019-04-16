use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use failure::Fallible;

/// The prefix used for serializing internal nodes.
pub const INTERNAL_NODE_PREFIX: u8 = 1;
/// The prefix used for serializing leaf nodes.
pub const LEAF_NODE_PREFIX: u8 = 0;
/// The prefix used for serializing subtree summaries.
pub const SUBTREE_PREFIX: u8 = 3;

/// The `Marshal` trait is used for marshaling and unmarshaling Urkel trees.
pub trait Marshal {
    /// Marshal the object into a binary form and return it as a new vector.
    fn marshal_binary(&self) -> Fallible<Vec<u8>>;
    /// Unmarshal from the given byte slice reference and modify `self`.
    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize>;
}

impl Marshal for u64 {
    fn marshal_binary(&self) -> Fallible<Vec<u8>> {
        let mut result: Vec<u8> = Vec::with_capacity(8);
        result.write_u64::<LittleEndian>(*self)?;
        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Fallible<usize> {
        if data.len() < 8 {
            Err(format_err!("urkel: malformed 64-bit integer"))
        } else {
            let mut reader = Cursor::new(data);
            *self = reader.read_u64::<LittleEndian>()?;
            Ok(8)
        }
    }
}
