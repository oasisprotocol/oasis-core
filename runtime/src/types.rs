//! Types used by the worker-host protocol.
use serde::{self, Deserializer, Serializer};
use serde_bytes::{self, ByteBuf};
use serde_derive::{Deserialize, Serialize};

use crate::common::{
    batch::{CallBatch, OutputBatch},
    crypto::{hash::Hash, signature::PublicKey},
    roothash::Block,
    sgx::avr::AVR,
};

/// Computed batch.
#[derive(Debug, Serialize, Deserialize)]
pub struct ComputedBatch {
    /// Batch of runtime outputs.
    pub outputs: OutputBatch,
    /// Batch of storage inserts.
    pub storage_inserts: Vec<(ByteBuf, u64)>,
    /// New state root hash.
    pub new_state_root: Hash,
}

/// Worker protocol message body.
#[derive(Debug, Serialize, Deserialize)]
pub enum Body {
    // An empty body.
    Empty {},

    // An error response.
    Error {
        message: String,
    },

    // Worker interface.
    WorkerPingRequest {},
    WorkerShutdownRequest {},
    WorkerAbortRequest {},
    WorkerAbortResponse {},
    WorkerCapabilityTEERakReportRequest {
        #[serde(with = "serde_bytes")]
        target_info: Vec<u8>,
    },
    WorkerCapabilityTEERakReportResponse {
        rak_pub: PublicKey,
        #[serde(with = "serde_bytes")]
        report: Vec<u8>,
    },
    WorkerCapabilityTEERakAvrRequest {
        avr: AVR,
    },
    WorkerCapabilityTEERakAvrResponse {},
    WorkerRPCCallRequest {
        #[serde(with = "serde_bytes")]
        request: Vec<u8>,
        state_root: Hash,
    },
    WorkerRPCCallResponse {
        #[serde(with = "serde_bytes")]
        response: Vec<u8>,
        storage_inserts: Vec<(ByteBuf, u64)>,
        new_state_root: Hash,
    },
    WorkerRuntimeCallBatchRequest {
        calls: CallBatch,
        block: Block,
    },
    WorkerRuntimeCallBatchResponse {
        batch: ComputedBatch,
    },

    // Host interface.
    HostRPCCallRequest {
        endpoint: String,
        #[serde(with = "serde_bytes")]
        request: Vec<u8>,
    },
    HostRPCCallResponse {
        #[serde(with = "serde_bytes")]
        response: Vec<u8>,
    },
    HostStorageGetRequest {
        key: Hash,
    },
    HostStorageGetResponse {
        #[serde(with = "serde_bytes")]
        value: Vec<u8>,
    },
    HostStorageGetBatchRequest {
        keys: Vec<Hash>,
    },
    HostStorageGetBatchResponse {
        values: Vec<Option<ByteBuf>>,
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
}

impl serde::Serialize for MessageType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> serde::Deserialize<'de> for MessageType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            1 => Ok(MessageType::Request),
            2 => Ok(MessageType::Response),
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
    /// Opentracing's SpanContext serialized in binary format.
    #[serde(with = "serde_bytes")]
    pub span_context: Vec<u8>,
}
