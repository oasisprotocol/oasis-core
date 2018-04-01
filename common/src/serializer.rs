//! Serialization and deserialization.
use std::io::{Cursor, Read, Write};
use std::str;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use protobuf::well_known_types::Empty;

use super::error::Result;

/// A serializer for a specific data type.
pub trait Serializable {
    /// Serialize message of a given type into raw bytes.
    fn write(&self) -> Result<Vec<u8>> {
        // Default implementation just uses `write_to`.
        let mut dst = Vec::new();
        self.write_to(&mut dst)?;

        Ok(dst)
    }

    /// Write the contents of self into given writer.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Notes
    ///
    /// Implementations should only write a single field of the given type into
    /// the input stream (e.g., they should assume that there may be multiple
    /// fields in the stream).
    fn write_to(&self, writer: &mut Write) -> Result<usize>;
}

/// A deserializer for a specific data type.
pub trait Deserializable {
    /// Deserialize message of a given type from raw bytes.
    fn read(value: &Vec<u8>) -> Result<Self>
    where
        Self: Sized,
    {
        // Default implementation just uses `read_from`.
        Self::read_from(&mut Cursor::new(value))
    }

    /// Deserialize message of a given type from reader.
    ///
    /// # Notes
    ///
    /// Implementations should only read a single field of the given type from
    /// the input stream (e.g., they should assume that there may be multiple
    /// fields in the stream).
    fn read_from(reader: &mut Read) -> Result<Self>
    where
        Self: Sized;
}

impl Serializable for str {
    fn write_to(&self, writer: &mut Write) -> Result<usize> {
        // Encode string as length (little-endian u32) + UTF-8 value.
        writer.write_u32::<LittleEndian>(self.len() as u32)?;
        writer.write(self.as_bytes())?;
        Ok(4 + self.len())
    }
}

impl Serializable for String {
    fn write_to(&self, writer: &mut Write) -> Result<usize> {
        // Encode string as length (little-endian u32) + UTF-8 value.
        writer.write_u32::<LittleEndian>(self.len() as u32)?;
        writer.write(self.as_bytes())?;
        Ok(4 + self.len())
    }
}

impl Deserializable for String {
    fn read_from(reader: &mut Read) -> Result<Self> {
        // Decode string as length (little-endian u32) + UTF-8 value.
        let length = reader.read_u32::<LittleEndian>()?;
        let mut buffer = vec![0; length as usize];
        reader.read_exact(&mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
}

impl Serializable for Vec<u8> {
    fn write_to(&self, writer: &mut Write) -> Result<usize> {
        // Encode bytes as length (little-endian u32) + value.
        writer.write_u32::<LittleEndian>(self.len() as u32)?;
        writer.write(self)?;
        Ok(4 + self.len())
    }
}

impl Deserializable for Vec<u8> {
    fn read_from(reader: &mut Read) -> Result<Self> {
        // Decode bytes as length (little-endian u32) + value.
        let length = reader.read_u32::<LittleEndian>()?;
        let mut buffer = vec![0; length as usize];
        reader.read_exact(&mut buffer)?;
        Ok(buffer)
    }
}

// Serializability for numeric types.
macro_rules! impl_serializable_numeric {
    ($num_type:ty, $reader:ident, $writer:ident, 1) => {
        impl Serializable for $num_type {
            fn write_to(&self, writer: &mut Write) -> Result<usize> {
                writer.$writer(*self)?;
                Ok(1)
            }
        }

        impl Deserializable for $num_type {
            fn read_from(reader: &mut Read) -> Result<Self> {
                Ok(reader.$reader()?)
            }
        }
    };

    ($num_type:ty, $reader:ident, $writer:ident, $size:expr) => {
        impl Serializable for $num_type {
            fn write_to(&self, writer: &mut Write) -> Result<usize> {
                writer.$writer::<LittleEndian>(*self)?;
                Ok($size)
            }
        }

        impl Deserializable for $num_type {
            fn read_from(reader: &mut Read) -> Result<Self> {
                Ok(reader.$reader::<LittleEndian>()?)
            }
        }
    }
}

impl_serializable_numeric!(u8, read_u8, write_u8, 1);
impl_serializable_numeric!(u16, read_u16, write_u16, 2);
impl_serializable_numeric!(u32, read_u32, write_u32, 4);
impl_serializable_numeric!(u64, read_u64, write_u64, 8);
impl_serializable_numeric!(i8, read_i8, write_i8, 1);
impl_serializable_numeric!(i16, read_i16, write_i16, 2);
impl_serializable_numeric!(i32, read_i32, write_i32, 4);
impl_serializable_numeric!(i64, read_i64, write_i64, 8);
impl_serializable_numeric!(f32, read_f32, write_f32, 4);
impl_serializable_numeric!(f64, read_f64, write_f64, 8);

impl Serializable for bool {
    fn write_to(&self, writer: &mut Write) -> Result<usize> {
        writer.write_u8(*self as u8)?;
        Ok(1)
    }
}

impl Deserializable for bool {
    fn read_from(reader: &mut Read) -> Result<Self> {
        Ok(reader.read_u8()? == 0)
    }
}

/// Serializable implementation generator for Protocol Buffers messages. We cannot
/// just implement this generically for all types satisfying the `protobuf::Message`
/// bound as Rust currently lacks specialization support.
#[macro_export]
macro_rules! impl_serializable_protobuf {
    ($message:ty) => {
        impl $crate::serializer::Serializable for $message {
            /// Serialize message of a given type into raw bytes.
            fn write(&self) -> $crate::error::Result<Vec<u8>> {
                use ::protobuf::Message;

                Ok(self.write_to_bytes()?)
            }

            /// Write the contents of self into given writer.
            ///
            /// Returns the number of bytes written.
            fn write_to(&self, writer: &mut ::std::io::Write) -> $crate::error::Result<usize> {
                use ::protobuf::Message;

                self.write_to_writer(writer)?;

                Ok(self.compute_size() as usize)
            }
        }

        impl $crate::serializer::Deserializable for $message {
            /// Deserialize message of a given type from raw bytes.
            fn read(value: &Vec<u8>) -> $crate::error::Result<Self> {
                Ok(::protobuf::parse_from_bytes(&value)?)
            }

            /// Deserialize message of a given type from reader.
            fn read_from(reader: &mut ::std::io::Read) -> $crate::error::Result<Self> {
                Ok(::protobuf::parse_from_reader(reader)?)
            }
        }
    }
}

impl_serializable_protobuf!(Empty);
