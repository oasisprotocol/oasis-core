//! Types used by the worker-host protocol.
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::{self, ByteBuf};
use sgx_types;

use ekiden_core::bytes::H256;
use ekiden_core::enclave::api as identity_api;
use ekiden_core::rpc::client::ClientEndpoint;
use ekiden_core::runtime::batch::{CallBatch, OutputBatch};
use ekiden_roothash_base::Block;

/// Computed batch.
#[derive(Debug, Serialize, Deserialize)]
pub struct ComputedBatch {
    /// Block this batch was computed against.
    pub block: Block,
    /// Batch of runtime calls.
    pub calls: CallBatch,
    /// Batch of runtime outputs.
    pub outputs: OutputBatch,
    /// New state root hash.
    pub new_state_root: H256,
}

/// Worker protocol message body.
#[derive(Debug, Serialize, Deserialize)]
pub enum Body {
    // An empty body.
    Empty,

    // An error response.
    Error {
        message: String,
    },

    // Worker interface.
    WorkerPingRequest,
    WorkerShutdownRequest,
    WorkerRpcCallRequest {
        #[serde(with = "serde_bytes")]
        request: Vec<u8>,
    },
    WorkerRpcCallResponse {
        #[serde(with = "serde_bytes")]
        response: Vec<u8>,
    },
    WorkerRuntimeCallBatchRequest {
        calls: CallBatch,
        block: Block,
        commit_storage: bool,
    },
    WorkerRuntimeCallBatchResponse {
        batch: ComputedBatch,
    },

    // Host interface.
    HostRpcCallRequest {
        endpoint: ClientEndpoint,
        #[serde(with = "serde_bytes")]
        request: Vec<u8>,
    },
    HostRpcCallResponse {
        #[serde(with = "serde_bytes")]
        response: Vec<u8>,
    },
    HostIasGetSpidRequest,
    HostIasGetSpidResponse {
        spid: [u8; 16],
    },
    HostIasGetQuoteTypeRequest,
    HostIasGetQuoteTypeResponse {
        quote_type: u32,
    },
    HostIasSigRlRequest {
        gid: sgx_types::sgx_epid_group_id_t,
    },
    HostIasSigRlResponse {
        #[serde(with = "serde_bytes")]
        sigrl: Vec<u8>,
    },
    HostIasReportRequest {
        #[serde(with = "serde_bytes")]
        quote: Vec<u8>,
    },
    HostIasReportResponse {
        report: identity_api::AvReport,
    },
    HostStorageGetRequest {
        key: H256,
    },
    HostStorageGetResponse {
        #[serde(with = "serde_bytes")]
        value: Vec<u8>,
    },
    HostStorageGetBatchRequest {
        keys: Vec<H256>,
    },
    HostStorageGetBatchResponse {
        values: Vec<Option<ByteBuf>>,
    },
    HostStorageInsertRequest {
        #[serde(with = "serde_bytes")]
        value: Vec<u8>,
        expiry: u64,
    },
    HostStorageInsertBatchRequest {
        values: Vec<(ByteBuf, u64)>,
    },
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum MessageType {
    /// Invalid message (should never be seen on the wire).
    Invalid = 0,
    /// Request.
    Request = 1,
    /// Response.
    Response = 2,
    /// Keep-alive.
    KeepAlive = 3,
}

impl Serialize for MessageType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for MessageType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            1 => Ok(MessageType::Request),
            2 => Ok(MessageType::Response),
            3 => Ok(MessageType::KeepAlive),
            _ => Err(serde::de::Error::custom("invalid message type")),
        }
    }
}

/// Worker protocol message.
#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    /// Unique request identifier.
    pub id: u64,
    /// Message type.
    pub message_type: MessageType,
    /// Message body.
    pub body: Body,
}
