//! Transaction protocol types.
use serde_cbor::Value;
use serde_derive::{Deserialize, Serialize};

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
