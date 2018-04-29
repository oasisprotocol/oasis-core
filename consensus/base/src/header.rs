//! Block header type.
use ekiden_common::bytes::{B256, H256};
use ekiden_common::hash::EncodedHash;
use ekiden_common::uint::U256;

use super::commitment::Commitable;

/// Block header.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Protocol version number.
    pub version: u16,
    /// Chain namespace.
    pub namespace: B256,
    /// Round.
    pub round: U256,
    /// Hash of the previous block.
    pub previous_hash: H256,
    /// Computation group hash.
    pub group_hash: H256,
    /// Transaction hash.
    pub transaction_hash: H256,
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

impl Commitable for Header {}
