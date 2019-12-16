//! Client for service defined in go/runtime/client/api.
use grpcio::{CallOption, Channel, Client, ClientSStreamReceiver, ClientUnaryReceiver, Result};
use serde_bytes::ByteBuf;
use serde_derive::{Deserialize, Serialize};

use oasis_core_runtime::{
    common::{
        crypto::hash::Hash,
        roothash::{AnnotatedBlock, Block},
        runtime::RuntimeId,
    },
    transaction::types::TxnBatch,
};

/// Special round number always referring to the latest round.
pub const ROUND_LATEST: u64 = u64::max_value();

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitTxRequest {
    pub runtime_id: RuntimeId,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetBlockRequest {
    pub runtime_id: RuntimeId,
    pub round: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetBlockByHashRequest {
    pub runtime_id: RuntimeId,
    pub block_hash: Hash,
}

// Transaction query result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxResult {
    pub block: Block,
    pub index: u32,
    #[serde(with = "serde_bytes")]
    pub input: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub output: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetTxRequest {
    pub runtime_id: RuntimeId,
    pub round: u64,
    pub index: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetTxByBlockHashRequest {
    pub runtime_id: RuntimeId,
    pub block_hash: Hash,
    pub index: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetTxsRequest {
    pub runtime_id: RuntimeId,
    pub round: u64,
    pub io_root: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryTxRequest {
    pub runtime_id: RuntimeId,
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryTxsRequest {
    pub runtime_id: RuntimeId,
    pub query: Query,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WaitBlockIndexedRequest {
    pub runtime_id: RuntimeId,
    pub round: u64,
}

grpc_method!(
    METHOD_SUBMIT_TX,
    "/oasis-core.RuntimeClient/SubmitTx",
    SubmitTxRequest,
    ByteBuf
);
grpc_method!(
    METHOD_GET_BLOCK,
    "/oasis-core.RuntimeClient/GetBlock",
    GetBlockRequest,
    Block
);
grpc_method!(
    METHOD_GET_BLOCK_BY_HASH,
    "/oasis-core.RuntimeClient/GetBlockByHash",
    GetBlockByHashRequest,
    Block
);
grpc_method!(
    METHOD_GET_TX,
    "/oasis-core.RuntimeClient/GetTx",
    GetTxRequest,
    TxResult
);
grpc_method!(
    METHOD_GET_TX_BY_BLOCK_HASH,
    "/oasis-core.RuntimeClient/GetTxByBlockHash",
    GetTxByBlockHashRequest,
    TxResult
);
grpc_method!(
    METHOD_GET_TXS,
    "/oasis-core.RuntimeClient/GetTxs",
    GetTxsRequest,
    TxnBatch
);
grpc_method!(
    METHOD_QUERY_TX,
    "/oasis-core.RuntimeClient/QueryTx",
    QueryTxRequest,
    TxResult
);
grpc_method!(
    METHOD_QUERY_TXS,
    "/oasis-core.RuntimeClient/QueryTxs",
    QueryTxsRequest,
    Vec<TxResult>
);
grpc_method!(
    METHOD_WAIT_BLOCK_INDEXED,
    "/oasis-core.RuntimeClient/WaitBlockIndexed",
    WaitBlockIndexedRequest,
    ()
);

grpc_stream!(
    METHOD_WATCH_BLOCKS,
    "/oasis-core.RuntimeClient/WatchBlocks",
    RuntimeId,
    AnnotatedBlock
);

/// A runtime gRPC service client.
#[derive(Clone)]
pub struct RuntimeClient {
    client: Client,
}

impl RuntimeClient {
    pub fn new(channel: Channel) -> Self {
        RuntimeClient {
            client: Client::new(channel),
        }
    }

    pub fn submit_tx(
        &self,
        request: &SubmitTxRequest,
        opt: CallOption,
    ) -> Result<ClientUnaryReceiver<ByteBuf>> {
        self.client
            .unary_call_async(&METHOD_SUBMIT_TX, &request, opt)
    }

    pub fn get_block(
        &self,
        request: &GetBlockRequest,
        opt: CallOption,
    ) -> Result<ClientUnaryReceiver<Block>> {
        self.client
            .unary_call_async(&METHOD_GET_BLOCK, &request, opt)
    }

    pub fn get_block_by_hash(
        &self,
        request: &GetBlockByHashRequest,
        opt: CallOption,
    ) -> Result<ClientUnaryReceiver<Block>> {
        self.client
            .unary_call_async(&METHOD_GET_BLOCK_BY_HASH, &request, opt)
    }

    pub fn get_tx(
        &self,
        request: &GetTxRequest,
        opt: CallOption,
    ) -> Result<ClientUnaryReceiver<TxResult>> {
        self.client.unary_call_async(&METHOD_GET_TX, &request, opt)
    }

    pub fn get_tx_by_block_hash(
        &self,
        request: &GetTxByBlockHashRequest,
        opt: CallOption,
    ) -> Result<ClientUnaryReceiver<TxResult>> {
        self.client
            .unary_call_async(&METHOD_GET_TX_BY_BLOCK_HASH, &request, opt)
    }

    pub fn get_txs(
        &self,
        request: &GetTxsRequest,
        opt: CallOption,
    ) -> Result<ClientUnaryReceiver<TxnBatch>> {
        self.client.unary_call_async(&METHOD_GET_TXS, &request, opt)
    }

    pub fn query_tx(
        &self,
        request: &QueryTxRequest,
        opt: CallOption,
    ) -> Result<ClientUnaryReceiver<TxResult>> {
        self.client
            .unary_call_async(&METHOD_QUERY_TX, &request, opt)
    }

    pub fn query_txs(
        &self,
        request: &QueryTxsRequest,
        opt: CallOption,
    ) -> Result<ClientUnaryReceiver<Vec<TxResult>>> {
        self.client
            .unary_call_async(&METHOD_QUERY_TXS, &request, opt)
    }

    pub fn wait_block_indexed(
        &self,
        request: &WaitBlockIndexedRequest,
        opt: CallOption,
    ) -> Result<ClientUnaryReceiver<()>> {
        self.client
            .unary_call_async(&METHOD_WAIT_BLOCK_INDEXED, &request, opt)
    }

    pub fn watch_blocks(
        &self,
        runtime_id: RuntimeId,
    ) -> Result<ClientSStreamReceiver<AnnotatedBlock>> {
        self.client
            .server_streaming(&METHOD_WATCH_BLOCKS, &runtime_id, Default::default())
    }
}
