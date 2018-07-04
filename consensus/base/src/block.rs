//! Block type.
use std::convert::TryFrom;

use ekiden_common::bytes::H256;
use ekiden_common::error::Error;
use ekiden_common::hash::EncodedHash;
use ekiden_common::uint::U256;
use ekiden_scheduler_base::CommitteeNode;

use ekiden_consensus_api as api;

use super::commitment::Reveal;
use super::header::Header;

/// Block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// Block header.
    pub header: Header,
    /// Designated computation group.
    pub computation_group: Vec<CommitteeNode>,
    /// Reveals from compute nodes in the same order as in the computation group.
    pub reveals: Vec<Option<Reveal>>,
}

impl Block {
    /// Generate a parent block from given child.
    pub fn new_parent_of(child: &Block) -> Block {
        let mut block = Block {
            header: Header {
                version: child.header.version,
                namespace: child.header.namespace,
                round: child.header.round + U256::from(1),
                previous_hash: child.header.get_encoded_hash(),
                group_hash: H256::zero(),
                input_hash: H256::zero(),
                output_hash: H256::zero(),
                state_root: H256::zero(),
                reveals_hash: H256::zero(),
            },
            computation_group: vec![],
            reveals: vec![],
        };

        block.update();
        block
    }

    /// Update header based on current block content.
    pub fn update(&mut self) {
        self.header.group_hash = self.computation_group.get_encoded_hash();
        self.header.reveals_hash = self.reveals.get_encoded_hash();
    }

    /// Check if block is internally consistent.
    ///
    /// This checks the following:
    ///   * Computation group matches the hash in the header.
    ///   * Reveals list matches the hash in the header.
    pub fn is_internally_consistent(&self) -> bool {
        self.computation_group.get_encoded_hash() == self.header.group_hash
            && self.reveals.get_encoded_hash() == self.header.reveals_hash
    }
}

impl TryFrom<api::Block> for Block {
    /// try_from Converts a protobuf block into a block.
    type Error = Error;
    fn try_from(a: api::Block) -> Result<Self, self::Error> {
        let header = Header::try_from(a.get_header().to_owned())?;
        let mut computation = Vec::new();
        for item in a.get_computation_group().iter() {
            computation.push(CommitteeNode::try_from(item.to_owned())?);
        }

        let mut reveals = Vec::new();
        for item in a.get_reveals().iter() {
            if item.get_data().is_empty() {
                reveals.push(None);
            } else {
                reveals.push(Some(Reveal::try_from(item.to_owned())?));
            }
        }
        Ok(Block {
            header: header,
            computation_group: computation,
            reveals: reveals,
        })
    }
}

impl Into<api::Block> for Block {
    /// into Converts a block into a protobuf `consensus::api::Block` representation.
    fn into(self) -> api::Block {
        let mut b = api::Block::new();
        b.set_header(self.header.into());

        let mut groups = Vec::new();
        for item in self.computation_group {
            groups.push(item.into());
        }
        b.set_computation_group(groups.into());

        let mut reveals = Vec::new();
        for item in self.reveals {
            match item {
                Some(item) => reveals.push(item.into()),
                None => reveals.push(api::Reveal::new()),
            }
        }
        b.set_reveals(reveals.into());
        b
    }
}
