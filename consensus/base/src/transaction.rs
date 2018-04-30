//! Transaction type.
use ekiden_common::bytes::H256;

/// Transaction (contract invocation).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Contract input.
    pub input: Vec<u8>,
    /// Hash over contract output.
    pub output_hash: H256,
}
