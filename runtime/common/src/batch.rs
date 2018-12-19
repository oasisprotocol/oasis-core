//! Batch type.
use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};

/// Internal module to efficiently serialize batches.
mod batch_serialize {
    use serde::{de::Deserializer,
                ser::{SerializeSeq, Serializer},
                Deserialize};
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

/// Batch of (encrypted) runtime calls.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallBatch(#[serde(with = "batch_serialize")] pub Vec<Vec<u8>>);

impl Deref for CallBatch {
    type Target = Vec<Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CallBatch {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<Vec<u8>>> for CallBatch {
    fn from(other: Vec<Vec<u8>>) -> CallBatch {
        CallBatch(other)
    }
}

impl From<VecDeque<Vec<u8>>> for CallBatch {
    fn from(other: VecDeque<Vec<u8>>) -> CallBatch {
        CallBatch(other.into())
    }
}

impl Into<Vec<Vec<u8>>> for CallBatch {
    fn into(self) -> Vec<Vec<u8>> {
        self.0.into()
    }
}

impl Into<VecDeque<Vec<u8>>> for CallBatch {
    fn into(self) -> VecDeque<Vec<u8>> {
        self.0.into()
    }
}

/// Batch of (encrypted) runtime outputs.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutputBatch(#[serde(with = "batch_serialize")] pub Vec<Vec<u8>>);

impl Deref for OutputBatch {
    type Target = Vec<Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for OutputBatch {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
