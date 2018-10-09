//! Block header type.
#[cfg(not(target_env = "sgx"))]
use std::convert::TryFrom;

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

#[cfg(not(target_env = "sgx"))]
use ekiden_roothash_api as api;

use ekiden_common::bytes::{B256, H256};
#[cfg(not(target_env = "sgx"))]
use ekiden_common::error::Error;
use ekiden_common::hash::EncodedHash;
use ekiden_common::uint::U256;

/// Block header.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Deserialize)]
pub struct Header {
    /// Protocol version number.
    pub version: u16,
    /// Chain namespace.
    pub namespace: B256,
    /// Round.
    pub round: U256,
    /// Timestamp (POSIX time).
    pub timestamp: u64,
    /// Hash of the previous block.
    pub previous_hash: H256,
    /// Computation group hash.
    pub group_hash: H256,
    /// Input hash.
    pub input_hash: H256,
    /// Output hash.
    pub output_hash: H256,
    /// State root hash.
    pub state_root: H256,
    /// Commitments hash.
    pub commitments_hash: H256,
}

impl Header {
    /// Check if this header is a parent of a child header.
    pub fn is_parent_of(&self, child: &Header) -> bool {
        self.previous_hash == child.get_encoded_hash()
    }
}

// NOTE: We need to implement a custom Serialize because we need canonical encoding,
//       e.g., fields sorted by name.
impl Serialize for Header {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut header = serializer.serialize_struct("Header", 10)?;
        header.serialize_field("commitments_hash", &self.commitments_hash)?;
        header.serialize_field("group_hash", &self.group_hash)?;
        header.serialize_field("input_hash", &self.input_hash)?;
        header.serialize_field("namespace", &self.namespace)?;
        header.serialize_field("output_hash", &self.output_hash)?;
        header.serialize_field("previous_hash", &self.previous_hash)?;
        header.serialize_field("round", &self.round)?;
        header.serialize_field("state_root", &self.state_root)?;
        header.serialize_field("timestamp", &self.timestamp)?;
        header.serialize_field("version", &self.version)?;
        header.end()
    }
}

#[cfg(not(target_env = "sgx"))]
impl TryFrom<api::Header> for Header {
    type Error = Error;
    fn try_from(a: api::Header) -> Result<Self, self::Error> {
        Ok(Header {
            version: a.get_version() as u16,
            namespace: B256::try_from(a.get_namespace())?,
            round: U256::try_from(a.get_round())?,
            timestamp: a.get_timestamp(),
            previous_hash: H256::try_from(a.get_previous_hash())?,
            group_hash: H256::try_from(a.get_group_hash())?,
            input_hash: H256::try_from(a.get_input_hash())?,
            output_hash: H256::try_from(a.get_output_hash())?,
            state_root: H256::try_from(a.get_state_root())?,
            commitments_hash: H256::try_from(a.get_commitments_hash())?,
        })
    }
}

#[cfg(not(target_env = "sgx"))]
impl Into<api::Header> for Header {
    fn into(self) -> api::Header {
        let mut h = api::Header::new();
        h.set_version(self.version as u32);
        h.set_namespace(self.namespace.to_vec());
        h.set_round(self.round.to_vec_big_endian_stripped());
        h.set_timestamp(self.timestamp);
        h.set_previous_hash(self.previous_hash.to_vec());
        h.set_group_hash(self.group_hash.to_vec());
        h.set_input_hash(self.input_hash.to_vec());
        h.set_output_hash(self.output_hash.to_vec());
        h.set_state_root(self.state_root.to_vec());
        h.set_commitments_hash(self.commitments_hash.to_vec());
        h
    }
}
