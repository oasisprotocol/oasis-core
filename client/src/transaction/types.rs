//! Transaction client types.
use serde_bytes::ByteBuf;
use serde_derive::{Deserialize, Serialize};

use ekiden_runtime::common::{crypto::hash::Hash, roothash::Block};

/// Special round number always referring to the latest round.
pub const ROUND_LATEST: u64 = u64::max_value();
/// Tag used for storing the Ekiden block hash.
pub const TAG_BLOCK_HASH: &'static [u8] = b"hblk";

/// A query condition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryCondition {
    /// The tag key that should be matched.
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    /// A list of tag values that the given tag key should have. They
    /// are combined using an OR query which means that any of the
    /// values will match.
    pub values: Vec<ByteBuf>,
}

/// A complex query against the index.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Query {
    /// An optional minimum round (inclusive).
    pub round_min: u64,
    /// An optional maximum round (exclusive).
    pub round_max: u64,
    /// The query conditions.
    ///
    /// They are combined using an AND query which means that all of
    /// the conditions must be satisfied for an item to match.
    pub conditions: Vec<QueryCondition>,
    /// The maximum number of results to return.
    pub limit: u64,
}

// The transaction query result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxnResult {
    pub block: Block,
    pub block_hash: Hash,
    pub index: u32,
    #[serde(with = "serde_bytes")]
    pub input: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub output: Vec<u8>,
}
