//! Opaque commitment types.
use std::convert::TryFrom;

use serde_bytes;

use ekiden_common::error::Error;
use ekiden_consensus_api as api;

/// Opaque backend-specific nonce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nonce {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

impl TryFrom<api::Nonce> for Nonce {
    /// Converts a protobuf `api::Nonce` into a `Nonce`.
    type Error = Error;
    fn try_from(mut other: api::Nonce) -> Result<Self, Error> {
        Ok(Nonce {
            data: other.take_data(),
        })
    }
}

impl Into<api::Nonce> for Nonce {
    /// Converts a nonce into a protobuf `api::Nonce` representation.
    fn into(self) -> api::Nonce {
        let mut other = api::Nonce::new();
        other.set_data(self.data);
        other
    }
}

/// Opaque backend-specific commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

impl TryFrom<api::Commitment> for Commitment {
    /// Converts a protobuf `api::Commitment` into a `Commitment`.
    type Error = Error;
    fn try_from(mut other: api::Commitment) -> Result<Self, Error> {
        Ok(Commitment {
            data: other.take_data(),
        })
    }
}

impl Into<api::Commitment> for Commitment {
    /// Converts a commitment into a protobuf `api::Commitment` representation.
    fn into(self) -> api::Commitment {
        let mut other = api::Commitment::new();
        other.set_data(self.data);
        other
    }
}

/// Opaque backend-specific reveal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reveal {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

impl TryFrom<api::Reveal> for Reveal {
    /// Converts a protobuf `api::Reveal` into a `Reveal`.
    type Error = Error;
    fn try_from(mut other: api::Reveal) -> Result<Self, Error> {
        Ok(Reveal {
            data: other.take_data(),
        })
    }
}

impl Into<api::Reveal> for Reveal {
    /// Converts a reveal into a protobuf `api::Reveal` representation.
    fn into(self) -> api::Reveal {
        let mut other = api::Reveal::new();
        other.set_data(self.data);
        other
    }
}
