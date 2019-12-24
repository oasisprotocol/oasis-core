//! Registry structures.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/registry/api.
//!
use super::{
    super::storage::mkvs::WriteLog,
    crypto::{hash, signature::SignatureBundle},
};
use serde_derive::{Deserialize, Serialize};

/// Runtime genesis information that is used to initialize runtime state in the first block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuntimeGenesis {
    /// State root that should be used at genesis time. If the runtime should start with empty state,
    /// this must be set to the empty hash.
    pub state_root: hash::Hash,

    /// State identified by the state_root. It may be empty iff all storage_receipts are valid or
    /// state_root is an empty hash or if used in network genesis (e.g. during consensus chain init).
    pub state: WriteLog,

    /// Storage receipts for the state root. The list may be empty or a signature in the list
    /// invalid iff the state is non-empty or state_root is an empty hash or if used in network
    /// genesis (e.g. during consensus chain init).
    pub storage_receipts: Vec<SignatureBundle>,

    /// Runtime round in the genesis.
    pub round: u64,
}
