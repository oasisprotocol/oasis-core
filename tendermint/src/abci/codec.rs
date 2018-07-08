//! Codec for ABCI Protocol Buffers streams.
use std::io::{Cursor, Write};

use bytes::{BufMut, BytesMut};
use integer_encoding::{VarInt, VarIntReader};
use protobuf::{self, Message};
use tokio_codec::{Decoder, Encoder};

use ekiden_common::error::{Error, Result};

use super::types;

/// Maximum Protocol Buffers message size.
///
/// Reference: https://github.com/tendermint/tendermint/blob/master/abci/types/messages.go
const MAX_MESSAGE_SIZE: i64 = 104_857_600; // 100MB

/// Codec for ABCI Protocol Buffers streams.
#[derive(Clone, Debug)]
pub struct AbciCodec;

impl AbciCodec {
    /// Create new ABCI codec.
    pub fn new() -> Self {
        AbciCodec
    }
}

impl Decoder for AbciCodec {
    type Item = types::Request;
    type Error = Error;

    fn decode(&mut self, buffer: &mut BytesMut) -> Result<Option<types::Request>> {
        let (length, offset) = {
            let mut cursor = Cursor::new(&buffer);

            // Decode varint-encoded u64 size prefix.
            if let Ok(length) = cursor.read_varint::<i64>() {
                if length < 0 || length > MAX_MESSAGE_SIZE {
                    return Err(Error::new("invalid message size prefix"));
                }

                (length as usize, cursor.position() as usize)
            } else {
                // Cannot decode length yet.
                return Ok(None);
            }
        };

        if buffer.len() < offset + length {
            return Ok(None);
        }

        // Decode message.
        let message = protobuf::parse_from_bytes(&buffer[offset..offset + length])?;
        buffer.split_to(offset + length);

        Ok(Some(message))
    }
}

impl Encoder for AbciCodec {
    type Item = types::Response;
    type Error = Error;

    fn encode(&mut self, message: types::Response, buffer: &mut BytesMut) -> Result<()> {
        // Encode Protocol BUffers message.
        let mut output = Vec::new();
        message.write_to_vec(&mut output)?;

        // Encode u64 varint size prefix.
        let length = i64::encode_var_vec(output.len() as i64);

        let mut writer = buffer.writer();
        writer.write(&length)?;
        writer.write(&output)?;

        Ok(())
    }
}
