//! Canonical CBOR serialization/deserialization functions.
use std::io::Write;

use serde::{Deserialize, Serialize};
pub use serde_cbor::value::{from_value, Value};
use serde_cbor::{self, Result};

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
