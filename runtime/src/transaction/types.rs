//! Transaction protocol types.
use std::{
    collections::VecDeque,
    ops::{Deref, DerefMut},
};

use serde_derive::{Deserialize, Serialize};

use super::rwset::ReadWriteSet;
use crate::common::cbor::Value;

/// Transaction call.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxnCall {
    /// Method name.
    pub method: String,
    /// Method arguments.
    pub args: Value,
}

/// Transaction call output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TxnOutput {
    /// Call invoked successfully.
    Success(Value),
    /// Call raised an error.
    Error(String),
}

/// The result of a successful CheckTx call.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TxnCheckResult {
    /// Predicted read/write set.
    pub predicted_rw_set: ReadWriteSet,
}

/// Internal module to efficiently serialize batches.
mod batch_serialize {
    use serde::{
        de::Deserializer,
        ser::{SerializeSeq, Serializer},
        Deserialize,
    };
    use serde_bytes::{ByteBuf, Bytes};

    pub fn serialize<S>(batch: &Vec<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(batch.len()))?;
        for call in batch {
            seq.serialize_element(&Bytes::new(&call[..]))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<ByteBuf>::deserialize(deserializer).map(|v| v.into_iter().map(|e| e.into()).collect())
    }
}

/// Batch of transaction inputs/outputs.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TxnBatch(#[serde(with = "batch_serialize")] pub Vec<Vec<u8>>);

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

    use crate::common::{cbor, crypto::hash::Hash};

    #[test]
    fn test_consistent_hash() {
        let batch = TxnBatch(vec![b"foo".to_vec(), b"bar".to_vec(), b"aaa".to_vec()]);
        let h = Hash::digest_bytes(&cbor::to_vec(&batch));
        assert_eq!(
            h,
            Hash::from("c451dd4fd065b815e784aac6b300e479b2167408f0eebbb95a8bd36b9e71e34d")
        );
    }
}
