//! Transaction protocol types.
use std::{
    collections::VecDeque,
    ops::{Deref, DerefMut},
};

use super::rwset::ReadWriteSet;

/// Transaction call.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
#[deprecated(note = "see oasis-core#3572")]
pub struct TxnCall {
    /// Method name.
    pub method: String,
    /// Method arguments.
    pub args: cbor::Value,
}

/// Transaction call output.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
#[deprecated(note = "see oasis-core#3572")]
pub enum TxnOutput {
    /// Call invoked successfully.
    Success(cbor::Value),
    /// Call raised an error.
    Error(String),
}

/// The result of a successful CheckTx call.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
#[deprecated(note = "see oasis-core#3572")]
pub struct TxnCheckResult {
    /// Predicted read/write set.
    pub predicted_rw_set: ReadWriteSet,
}

/// Batch of transaction inputs/outputs.
#[derive(Clone, Debug, Default, Eq, PartialEq, cbor::Encode, cbor::Decode)]
#[cbor(transparent)]
pub struct TxnBatch(pub Vec<Vec<u8>>);

impl TxnBatch {
    pub fn new(txs: Vec<Vec<u8>>) -> TxnBatch {
        TxnBatch(txs)
    }
}

impl Deref for TxnBatch {
    type Target = Vec<Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TxnBatch {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<Vec<u8>>> for TxnBatch {
    fn from(other: Vec<Vec<u8>>) -> TxnBatch {
        TxnBatch(other)
    }
}

impl From<VecDeque<Vec<u8>>> for TxnBatch {
    fn from(other: VecDeque<Vec<u8>>) -> TxnBatch {
        TxnBatch(other.into())
    }
}

impl Into<Vec<Vec<u8>>> for TxnBatch {
    fn into(self) -> Vec<Vec<u8>> {
        self.0.into()
    }
}

impl Into<VecDeque<Vec<u8>>> for TxnBatch {
    fn into(self) -> VecDeque<Vec<u8>> {
        self.0.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::common::crypto::hash::Hash;

    #[test]
    fn test_consistent_hash() {
        let batch = TxnBatch(vec![b"foo".to_vec(), b"bar".to_vec(), b"aaa".to_vec()]);
        let h = Hash::digest_bytes(&cbor::to_vec(batch));
        assert_eq!(
            h,
            Hash::from("c451dd4fd065b815e784aac6b300e479b2167408f0eebbb95a8bd36b9e71e34d")
        );
    }
}
