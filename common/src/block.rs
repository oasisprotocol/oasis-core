//! Block type.
use std::convert::TryFrom;

use bytes::H256;
use error::Error;
use hash::{empty_hash, EncodedHash};
use header::Header;
use uint::U256;

use ekiden_common_api as api;

/// Block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// Block header.
    pub header: Header,
}

impl Block {
    /// Generate a parent block from given child.
    pub fn new_parent_of(child: &Block) -> Block {
        Block {
            header: Header {
                version: child.header.version,
                namespace: child.header.namespace,
                round: child.header.round + U256::from(1),
                timestamp: 0,
                previous_hash: child.header.get_encoded_hash(),
                group_hash: H256::zero(),
                input_hash: H256::zero(),
                output_hash: H256::zero(),
                state_root: H256::zero(),
                commitments_hash: empty_hash(),
            },
        }
    }
}

impl TryFrom<api::Block> for Block {
    /// try_from Converts a protobuf block into a block.
    type Error = Error;
    fn try_from(a: api::Block) -> Result<Self, self::Error> {
        let header = Header::try_from(a.get_header().to_owned())?;
        Ok(Block { header: header })
    }
}

impl Into<api::Block> for Block {
    /// Converts a block into a protobuf `api::Block` representation.
    fn into(self) -> api::Block {
        let mut b = api::Block::new();
        b.set_header(self.header.into());
        b
    }
}
