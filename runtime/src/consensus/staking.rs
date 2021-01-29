//! Consensus staking structures.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/staking/api.
//!
use serde::{Deserialize, Serialize};
use serde_repr::*;

use crate::{common::quantity::Quantity, consensus::address::Address};

/// A stake transfer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Transfer {
    pub to: Address,
    pub amount: Quantity,
}

/// A withdrawal from an account.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Withdraw {
    pub from: Address,
    pub amount: Quantity,
}

/// Kind of staking threshold.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize_repr, Deserialize_repr)]
#[repr(i32)]
pub enum ThresholdKind {
    /// Entity staking threshold.
    #[serde(rename = "entity")]
    KindEntity = 0,
    /// Validator node staking threshold.
    #[serde(rename = "node-validator")]
    KindNodeValidator = 1,
    /// Compute node staking threshold.
    #[serde(rename = "node-compute")]
    KindNodeCompute = 2,
    /// Storage node staking threshold.
    #[serde(rename = "node-storage")]
    KindNodeStorage = 3,
    /// Keymanager node staking threshold.
    #[serde(rename = "node-keymanager")]
    KindNodeKeyManager = 4,
    /// Compute runtime staking threshold.
    #[serde(rename = "runtime-compute")]
    KindRuntimeCompute = 5,
    /// Keymanager runtime staking threshold.
    #[serde(rename = "runtime-keymanager")]
    KindRuntimeKeyManager = 6,
}
