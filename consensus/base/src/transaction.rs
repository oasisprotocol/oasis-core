//! Transaction type.
use std::convert::TryFrom;

use ekiden_common::error::Error;
use ekiden_consensus_api as api;

use ekiden_common::bytes::H256;

/// Transaction (contract invocation).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Contract input.
    pub input: Vec<u8>,
    /// Hash over contract output.
    pub output_hash: H256,
}

impl TryFrom<api::Transaction> for Transaction {
    type Error = Error;
    fn try_from(a: api::Transaction) -> Result<Self, self::Error> {
        Ok(Transaction {
            input: a.get_input().to_vec(),
            output_hash: H256::from(a.get_output_hash()),
        })
    }
}

impl Into<api::Transaction> for Transaction {
    fn into(self) -> api::Transaction {
        let mut t = api::Transaction::new();
        t.set_input(self.input.to_vec());
        t.set_output_hash(self.output_hash.to_vec());
        t
    }
}
