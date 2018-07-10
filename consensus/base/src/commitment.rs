//! Opaque commitment types.
use std::convert::TryFrom;

use serde_bytes;

use ekiden_common::error::Error;
use ekiden_consensus_api as api;

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
