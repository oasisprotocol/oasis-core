//! Types used by the worker-host protocol.
use serde::{self, Deserializer, Serializer};
use serde_bytes;
use serde_derive::{Deserialize, Serialize};

use crate::{
    common::{
        crypto::{
            hash::Hash,
            signature::{PublicKey, Signature},
        },
        roothash::{Block, ComputeResultsHeader},
        sgx::avr::AVR,
    },
    storage::mkvs::{urkel::sync, WriteLog},
    transaction::types::TxnBatch,
};

/// Computed batch.
#[derive(Debug, Serialize, Deserialize)]
pub struct ComputedBatch {
    /// Compute results header.
    pub header: ComputeResultsHeader,
    /// Log that generates the I/O tree.
    pub io_write_log: WriteLog,
    /// Log of changes to the state tree.
    pub state_write_log: WriteLog,
    /// If this runtime uses a TEE, then this is the signature of the batch's
    /// BatchSigMessage with the node's RAK for this runtime.
    pub rak_sig: Signature,
}

/// Storage sync request.
#[derive(Debug, Serialize, Deserialize)]
pub enum StorageSyncRequest {
    SyncGet(sync::GetRequest),
    SyncGetPrefixes(sync::GetPrefixesRequest),
    SyncIterate(sync::IterateRequest),
}

/// Storage sync response.
#[derive(Debug, Serialize, Deserialize)]
pub enum StorageSyncResponse {
    ProofResponse(sync::ProofResponse),
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

    // Runtime worker interface.
    WorkerInfoRequest {},
    WorkerInfoResponse {
        protocol_version: u64,
        runtime_version: u64,
    },
    WorkerPingRequest {},
    WorkerShutdownRequest {},
    WorkerAbortRequest {},
    WorkerAbortResponse {},
    WorkerCapabilityTEERakInitRequest {
        #[serde(with = "serde_bytes")]
        target_info: Vec<u8>,
    },
    WorkerCapabilityTEERakInitResponse {},
    WorkerCapabilityTEERakReportRequest {},
    WorkerCapabilityTEERakReportResponse {
        rak_pub: PublicKey,
        #[serde(with = "serde_bytes")]
        report: Vec<u8>,
        nonce: String,
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
        write_log: WriteLog,
        new_state_root: Hash,
    },
    WorkerLocalRPCCallRequest {
        #[serde(with = "serde_bytes")]
        request: Vec<u8>,
        state_root: Hash,
    },
    WorkerLocalRPCCallResponse {
        #[serde(with = "serde_bytes")]
        response: Vec<u8>,
    },
    WorkerCheckTxBatchRequest {
        inputs: TxnBatch,
        block: Block,
    },
    WorkerCheckTxBatchResponse {
        results: TxnBatch,
    },
    WorkerExecuteTxBatchRequest {
        io_root: Hash,
        inputs: TxnBatch,
        block: Block,
    },
    WorkerExecuteTxBatchResponse {
        batch: ComputedBatch,
    },

    // Host interface.
    HostKeyManagerPolicyRequest {},
    HostKeyManagerPolicyResponse {
        #[serde(with = "serde_bytes")]
        signed_policy_raw: Vec<u8>,
    },
    HostRPCCallRequest {
        endpoint: String,
        #[serde(with = "serde_bytes")]
        request: Vec<u8>,
    },
    HostRPCCallResponse {
        #[serde(with = "serde_bytes")]
        response: Vec<u8>,
    },
    HostStorageSyncRequest {
        #[serde(flatten)]
        request: StorageSyncRequest,
    },
    HostStorageSyncResponse {
        #[serde(flatten)]
        response: StorageSyncResponse,
    },
    HostStorageSyncSerializedResponse {
        #[serde(with = "serde_bytes")]
        serialized: Vec<u8>,
    },
    HostLocalStorageGetRequest {
        #[serde(with = "serde_bytes")]
        key: Vec<u8>,
    },
    HostLocalStorageGetResponse {
        #[serde(with = "serde_bytes")]
        value: Vec<u8>,
    },
    HostLocalStorageSetRequest {
        #[serde(with = "serde_bytes")]
        key: Vec<u8>,
        #[serde(with = "serde_bytes")]
        value: Vec<u8>,
    },
    HostLocalStorageSetResponse {},
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
