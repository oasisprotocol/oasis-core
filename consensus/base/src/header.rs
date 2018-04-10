//! Block header type.
use ekiden_common::bytes::{B256, H256};
use ekiden_common::hash::EncodedHash;
use ekiden_common::rlp::{Decodable, DecoderError, Encodable, RlpStream, UntrustedRlp};
use ekiden_common::uint::U256;

use super::commitment::Commitable;

/// Block header.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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

impl Encodable for Header {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(7);
        stream.append(&self.version);
        stream.append(&self.namespace);
        stream.append(&self.round);
        stream.append(&self.previous_hash);
        stream.append(&self.group_hash);
        stream.append(&self.transaction_hash);
        stream.append(&self.state_root);
        stream.append(&self.commitments_hash);
    }
}

impl Decodable for Header {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            version: rlp.val_at(0)?,
            namespace: rlp.val_at(1)?,
            round: rlp.val_at(2)?,
            previous_hash: rlp.val_at(3)?,
            group_hash: rlp.val_at(4)?,
            transaction_hash: rlp.val_at(5)?,
            state_root: rlp.val_at(6)?,
            commitments_hash: rlp.val_at(7)?,
        })
    }
}

impl Commitable for Header {}
