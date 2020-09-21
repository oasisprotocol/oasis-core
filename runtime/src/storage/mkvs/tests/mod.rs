//! Helpers for testing MKVS trees.
use std::fmt;

use base64;
use serde::{self, Deserialize};

/// Tree operation kind.
#[derive(Clone, Debug, Deserialize)]
pub enum OpKind {
    Insert,
    Remove,
    Get,
    IteratorSeek,
}

/// Tree operation used in test vectors.
#[derive(Clone, Debug, Deserialize)]
pub struct Op {
    /// Operation kind.
    pub op: OpKind,
    /// Key that is inserted, removed or looked up.
    #[serde(default, deserialize_with = "deserialize_base64")]
    pub key: Option<Vec<u8>>,
    /// Value that is inserted or that is expected for the given key during lookup.
    #[serde(default, deserialize_with = "deserialize_base64")]
    pub value: Option<Vec<u8>>,
    /// Key that is expected for the given operation (e.g., iterator seek).
    #[serde(default, deserialize_with = "deserialize_base64")]
    pub expected_key: Option<Vec<u8>>,
}

/// A MKVS tree test vector (a series of tree operations).
pub type TestVector = Vec<Op>;

fn deserialize_base64<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    struct Base64Visitor;

    impl<'de> serde::de::Visitor<'de> for Base64Visitor {
        type Value = Option<Vec<u8>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "base64 ASCII text")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            base64::decode(v)
                .map_err(serde::de::Error::custom)
                .map(Some)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_str(Base64Visitor)
}
