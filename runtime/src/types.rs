//! Types used by the worker-host protocol.
use serde::{self, ser::SerializeSeq, Deserializer, Serializer};
use serde_bytes::{self, Bytes};
use serde_derive::{Deserialize, Serialize};

use crate::{
    common::{
        crypto::{
            hash::Hash,
            signature::{PublicKey, Signature},
        },
        roothash::Block,
        sgx::avr::AVR,
    },
    storage::mkvs::WriteLog,
    transaction::types::TxnBatch,
};

/// Batch attestation context.
#[cfg_attr(not(target_env = "sgx"), allow(unused))]
pub const BATCH_HASH_CONTEXT: [u8; 8] = *b"EkBatch-";

/// Batch attestation parameters.
#[derive(Serialize)]
pub struct BatchSigMessage<'a> {
    /// The block (partial fields) that we computed this batch on.
    pub previous_block: &'a Block,
    /// The hash of the input TxnBatch.
    pub input_hash: &'a Hash,
    /// The hash of the output TxnBatch.
    pub output_hash: &'a Hash,
    /// The hash of serialized tags.
    pub tags_hash: &'a Hash,
    /// The root hash of the state after computing this batch.
    pub state_root: &'a Hash,
}

/// Value of a tag's transaction index when the tag refers to the block.
pub const TAG_TXN_INDEX_BLOCK: i32 = -1;

/// Tag is a key/value pair of arbitrary byte blobs with runtime-dependent
/// semantics which can be indexed to allow easier lookup of blocks and
/// transactions on runtime clients.
#[derive(Debug, Deserialize)]
pub struct Tag {
    // A transaction index that this tag belongs to.
    //
    // In case the value is TAG_TXN_INDEX_BLOCK, the tag instead refers
    // to the block.
    pub txn_index: i32,
    /// The tag key.
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    /// The tag value.
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

impl serde::Serialize for Tag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(3))?;
        seq.serialize_element(&self.txn_index)?;
        seq.serialize_element(&Bytes::new(&self.key))?;
        seq.serialize_element(&Bytes::new(&self.value))?;
        seq.end()
    }
}

/// Computed batch.
#[derive(Debug, Serialize, Deserialize)]
pub struct ComputedBatch {
    /// Batch of runtime outputs.
    pub outputs: TxnBatch,
    /// Log of changes to the storage tree.
    pub write_log: WriteLog,
    /// New state root hash.
    pub new_state_root: Hash,
    /// Runtime-specific indexable tags.
    pub tags: Vec<Tag>,
    /// If this runtime uses a TEE, then this is the signature of the batch's
    /// BatchSigMessage with the node's RAK for this runtime.
    pub rak_sig: Signature,
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
        calls: TxnBatch,
        block: Block,
    },
    WorkerCheckTxBatchResponse {
        results: TxnBatch,
    },
    WorkerExecuteTxBatchRequest {
        calls: TxnBatch,
        block: Block,
    },
    WorkerExecuteTxBatchResponse {
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
    HostStorageSyncGetSubtreeRequest {
        root_hash: Hash,
        node_path: Hash,
        node_depth: u8,
        max_depth: u8,
    },
    HostStorageSyncGetPathRequest {
        root_hash: Hash,
        key: Hash,
        start_depth: u8,
    },
    HostStorageSyncGetNodeRequest {
        root_hash: Hash,
        node_path: Hash,
        node_depth: u8,
    },
    HostStorageSyncGetValueRequest {
        root_hash: Hash,
        value_id: Hash,
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
