//! Canonical CBOR serialization/deserialization functions.
use std::io::{Read, Write};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_cbor::{self, Result};
pub use serde_cbor::{
    value::{from_value, Value},
    Error,
};

/// Convert a value to a `Value`.
pub fn to_value<T>(value: T) -> Value
where
    T: Serialize,
{
    serde_cbor::value::to_value(value).unwrap()
}

/// Serializes a value to a vector.
pub fn to_vec<T>(value: &T) -> Vec<u8>
where
    T: Serialize,
{
    // Use to_value first to force serialization into canonical format.
    serde_cbor::to_vec(&to_value(&value)).unwrap()
}

/// Serializes a value to a writer.
pub fn to_writer<W, T>(writer: W, value: &T)
where
    W: Write,
    T: Serialize,
{
    // Use to_value first to force serialization into canonical format.
    serde_cbor::to_writer(writer, &to_value(&value)).unwrap()
}

/// Deserializes a slice to a value.
pub fn from_slice<'a, T>(slice: &'a [u8]) -> Result<T>
where
    T: Deserialize<'a>,
{
    serde_cbor::from_slice(slice)
}

/// Deserializes data from a reader to a value.
pub fn from_reader<T, R>(reader: R) -> Result<T>
where
    T: DeserializeOwned,
    R: Read,
{
    serde_cbor::from_reader(reader)
}
