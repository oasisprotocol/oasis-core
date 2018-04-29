//! Batch type.
use std::ops::{Deref, DerefMut};

/// Batch of (encrypted) contract calls.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallBatch(pub Vec<Vec<u8>>);

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

/// Batch of (encrypted) contract outputs.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutputBatch(pub Vec<Vec<u8>>);

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
