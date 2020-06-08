use std::io::Cursor;

use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

/// The `Marshal` trait is used for marshaling and unmarshaling MKVS trees.
pub trait Marshal {
    /// Marshal the object into a binary form and return it as a new vector.
    fn marshal_binary(&self) -> Result<Vec<u8>>;
    /// Unmarshal from the given byte slice reference and modify `self`.
    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<usize>;
}

impl Marshal for u16 {
    fn marshal_binary(&self) -> Result<Vec<u8>> {
        let mut result: Vec<u8> = Vec::with_capacity(2);
        result.write_u16::<LittleEndian>(*self)?;
        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 2 {
            Err(anyhow!("mkvs: malformed 16-bit integer"))
        } else {
            let mut reader = Cursor::new(data);
            *self = reader.read_u16::<LittleEndian>()?;
            Ok(2)
        }
    }
}

impl Marshal for u32 {
    fn marshal_binary(&self) -> Result<Vec<u8>> {
        let mut result: Vec<u8> = Vec::with_capacity(4);
        result.write_u32::<LittleEndian>(*self)?;
        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 4 {
            Err(anyhow!("mkvs: malformed 32-bit integer"))
        } else {
            let mut reader = Cursor::new(data);
            *self = reader.read_u32::<LittleEndian>()?;
            Ok(4)
        }
    }
}

impl Marshal for u64 {
    fn marshal_binary(&self) -> Result<Vec<u8>> {
        let mut result: Vec<u8> = Vec::with_capacity(8);
        result.write_u64::<LittleEndian>(*self)?;
        Ok(result)
    }

    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 8 {
            Err(anyhow!("mkvs: malformed 64-bit integer"))
        } else {
            let mut reader = Cursor::new(data);
            *self = reader.read_u64::<LittleEndian>()?;
            Ok(8)
        }
    }
}
