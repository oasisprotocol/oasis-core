//! Codec for the worker protocol framing format.
use std::io::Cursor;

use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, BytesMut};
use serde_cbor::{self, SerializerOptions};
use tokio_codec::{Decoder, Encoder};

use ekiden_core::error::{Error, Result};

use super::types::Message;

/// Maximum message size.
const MAX_MESSAGE_SIZE: usize = 104_857_600; // 100MB

/// Codec for the worker protocol framing format.
#[derive(Clone, Debug)]
pub struct Codec;

impl Codec {
    /// Create new codec.
    pub fn new() -> Self {
        Codec
    }
}

impl Decoder for Codec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, buffer: &mut BytesMut) -> Result<Option<Message>> {
        if buffer.len() < 4 {
            // Cannot decode length yet.
            return Ok(None);
        }

        // Decode message.
        let (message, length) = {
            let mut cursor = Cursor::new(&buffer);
            let length = cursor.read_u32::<BigEndian>()? as usize;
            if length > MAX_MESSAGE_SIZE {
                return Err(Error::new("message too large"));
            }

            if buffer.len() < 4 + length {
                // Cannot decode value yet.
                return Ok(None);
            }

            (serde_cbor::from_slice(&buffer[4..4 + length])?, length)
        };
        buffer.split_to(4 + length);

        Ok(Some(message))
    }
}

impl Encoder for Codec {
    type Item = Message;
    type Error = Error;

    fn encode(&mut self, message: Message, buffer: &mut BytesMut) -> Result<()> {
        // Encode output and size prefix.
        let output = serde_cbor::to_vec_with_options(
            &message,
            &SerializerOptions {
                packed: false,
                enum_as_map: true,
            },
        )?;
        if output.len() > MAX_MESSAGE_SIZE {
            return Err(Error::new("message too large"));
        }

        buffer.reserve(4 + output.len());
        buffer.put_u32_be(output.len() as u32);
        buffer.put(&output);

        Ok(())
    }
}
