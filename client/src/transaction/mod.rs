//! Transaction client.

pub mod api;
mod block_watcher;
pub mod client;
pub mod macros;
pub mod snapshot;

// Re-exports.
pub use self::{
    api::client::{Query, QueryCondition, ROUND_LATEST},
    client::TxnClient,
};
