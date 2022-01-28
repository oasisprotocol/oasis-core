//! Types used by the worker-host protocol.
use std::collections::BTreeMap;

use thiserror::Error;

use crate::{
    common::{
        crypto::{
            hash::Hash,
            signature::{PublicKey, Signature},
        },
        namespace::Namespace,
        sgx::avr::AVR,
        version::Version,
    },
    consensus::{
        beacon::EpochTime,
        roothash::{self, Block, ComputeResultsHeader, Header},
        LightBlock,
    },
    storage::mkvs::{sync, WriteLog},
    transaction::types::TxnBatch,
};

/// Name of the batch weight limit runtime query method.
pub const BATCH_WEIGHT_LIMIT_QUERY_METHOD: &'static str = "internal.BatchWeightLimits";

/// Computed batch.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
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
    /// Messages emitted by the runtime.
    pub messages: Vec<roothash::Message>,
}

/// Storage sync request.
#[derive(Debug, cbor::Encode, cbor::Decode)]
pub enum StorageSyncRequest {
    SyncGet(sync::GetRequest),
    SyncGetPrefixes(sync::GetPrefixesRequest),
    SyncIterate(sync::IterateRequest),
}

#[derive(Debug)]
pub struct StorageSyncRequestWithEndpoint {
    pub endpoint: HostStorageEndpoint,
    pub request: StorageSyncRequest,
}

impl cbor::Encode for StorageSyncRequestWithEndpoint {
    fn into_cbor_value(self) -> cbor::Value {
        let mut request = cbor::EncodeAsMap::into_cbor_map(self.request);
        // Add endpoint to the given map.
        let key = cbor::values::IntoCborValue::into_cbor_value("endpoint");
        request.push((key, self.endpoint.into_cbor_value()));
        cbor::Value::Map(request)
    }
}

impl cbor::Decode for StorageSyncRequestWithEndpoint {
    fn try_from_cbor_value(value: cbor::Value) -> Result<Self, cbor::DecodeError> {
        match value {
            cbor::Value::Map(mut items) => {
                // Take the endpoint field from the map and decode the rest.
                let key = cbor::values::IntoCborValue::into_cbor_value("endpoint");
                let (index, _) = items
                    .iter()
                    .enumerate()
                    .find(|(_, v)| v.0 == key)
                    .ok_or(cbor::DecodeError::MissingField)?;
                let endpoint = items.remove(index).1;

                Ok(Self {
                    endpoint: cbor::Decode::try_from_cbor_value(endpoint)?,
                    request: cbor::Decode::try_from_cbor_value(cbor::Value::Map(items))?,
                })
            }
            _ => Err(cbor::DecodeError::UnexpectedType),
        }
    }
}

/// Storage sync response.
#[derive(Debug, cbor::Encode, cbor::Decode)]
pub enum StorageSyncResponse {
    ProofResponse(sync::ProofResponse),
}

/// Host storage endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
#[repr(u8)]
pub enum HostStorageEndpoint {
    Runtime = 0,
    Consensus = 1,
}

/// Runtime host protocol message body.
#[derive(Debug, cbor::Encode, cbor::Decode)]
pub enum Body {
    // An empty body.
    Empty {},

    // An error response.
    Error(Error),

    // Runtime interface.
    RuntimeInfoRequest(RuntimeInfoRequest),
    RuntimeInfoResponse(RuntimeInfoResponse),
    RuntimePingRequest {},
    RuntimeShutdownRequest {},
    RuntimeAbortRequest {},
    RuntimeAbortResponse {},
    RuntimeCapabilityTEERakInitRequest {
        target_info: Vec<u8>,
    },
    RuntimeCapabilityTEERakInitResponse {},
    RuntimeCapabilityTEERakReportRequest {},
    RuntimeCapabilityTEERakReportResponse {
        rak_pub: PublicKey,
        report: Vec<u8>,
        nonce: String,
    },
    RuntimeCapabilityTEERakAvrRequest {
        avr: AVR,
    },
    RuntimeCapabilityTEERakAvrResponse {},
    RuntimeRPCCallRequest {
        request: Vec<u8>,
    },
    RuntimeRPCCallResponse {
        response: Vec<u8>,
    },
    RuntimeLocalRPCCallRequest {
        request: Vec<u8>,
    },
    RuntimeLocalRPCCallResponse {
        response: Vec<u8>,
    },
    RuntimeCheckTxBatchRequest {
        consensus_block: LightBlock,
        inputs: TxnBatch,
        block: Block,
        epoch: EpochTime,
        max_messages: u32,
    },
    RuntimeCheckTxBatchResponse {
        results: Vec<CheckTxResult>,
    },
    RuntimeExecuteTxBatchRequest {
        consensus_block: LightBlock,
        round_results: roothash::RoundResults,
        io_root: Hash,
        #[cbor(optional)]
        inputs: Option<TxnBatch>,
        #[cbor(optional, default)]
        in_msgs: Vec<roothash::IncomingMessage>,
        block: Block,
        epoch: EpochTime,
        max_messages: u32,
    },
    RuntimeExecuteTxBatchResponse {
        batch: ComputedBatch,
        #[cbor(optional)]
        batch_weight_limits: Option<BTreeMap<TransactionWeight, u64>>,
    },
    RuntimeKeyManagerPolicyUpdateRequest {
        signed_policy_raw: Vec<u8>,
    },
    RuntimeKeyManagerPolicyUpdateResponse {},
    RuntimeQueryRequest {
        consensus_block: LightBlock,
        header: Header,
        epoch: EpochTime,
        max_messages: u32,
        method: String,
        #[cbor(optional, default)]
        args: Vec<u8>,
    },
    RuntimeQueryResponse {
        #[cbor(optional, default)]
        data: Vec<u8>,
    },
    RuntimeConsensusSyncRequest {
        height: u64,
    },
    RuntimeConsensusSyncResponse {},

    // Host interface.
    HostRPCCallRequest {
        endpoint: String,
        request: Vec<u8>,
    },
    HostRPCCallResponse {
        response: Vec<u8>,
    },
    HostStorageSyncRequest(StorageSyncRequestWithEndpoint),
    HostStorageSyncResponse(StorageSyncResponse),
    HostLocalStorageGetRequest {
        key: Vec<u8>,
    },
    HostLocalStorageGetResponse {
        value: Vec<u8>,
    },
    HostLocalStorageSetRequest {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    HostLocalStorageSetResponse {},
    HostFetchConsensusBlockRequest {
        height: u64,
    },
    HostFetchConsensusBlockResponse {
        block: LightBlock,
    },
}

/// A serializable error.
#[derive(Clone, Debug, Default, Error, cbor::Encode, cbor::Decode)]
#[error("module: {module} code: {code} message: {message}")]
pub struct Error {
    #[cbor(optional)]
    #[cbor(default)]
    pub module: String,

    #[cbor(optional)]
    #[cbor(default)]
    pub code: u32,

    #[cbor(optional)]
    #[cbor(default)]
    pub message: String,
}

impl Error {
    /// Create a new error.
    pub fn new(module: &str, code: u32, msg: &str) -> Self {
        Self {
            module: module.to_owned(),
            code,
            message: msg.to_owned(),
        }
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Self {
            module: "unknown".to_string(),
            code: 1,
            message: err.to_string(),
        }
    }
}

/// Runtime information request.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
pub struct RuntimeInfoRequest {
    pub runtime_id: Namespace,
    pub consensus_backend: String,
    pub consensus_protocol_version: Version,
    pub consensus_chain_context: String,

    #[cbor(optional)]
    #[cbor(default)]
    #[cbor(skip_serializing_if = "BTreeMap::is_empty")]
    pub local_config: BTreeMap<String, cbor::Value>,
}

/// Runtime information response.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
pub struct RuntimeInfoResponse {
    pub protocol_version: Version,
    pub runtime_version: Version,
}

/// Result of a CheckTx operation.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct CheckTxResult {
    pub error: Error,
    pub meta: Option<CheckTxMetadata>,
}

/// CheckTx transaction metadata.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct CheckTxMetadata {
    #[cbor(optional)]
    #[cbor(default)]
    #[cbor(skip_serializing_if = "num_traits::Zero::is_zero")]
    pub priority: u64,

    #[cbor(optional)]
    pub weights: Option<BTreeMap<TransactionWeight, u64>>,
}

/// Transaction weight kind.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransactionWeight {
    /// Consensus messages weight key.
    ConsensusMessages,
    /// Runtime specific weight key.
    Custom(String),
}

impl From<&str> for TransactionWeight {
    fn from(s: &str) -> Self {
        match s {
            "consensus_messages" => Self::ConsensusMessages,
            _ => Self::Custom(s.to_string()),
        }
    }
}

impl cbor::Encode for TransactionWeight {
    fn into_cbor_value(self) -> cbor::Value {
        match self {
            Self::ConsensusMessages => cbor::Value::TextString("consensus_messages".to_string()),
            Self::Custom(other) => cbor::Value::TextString(other),
        }
    }
}

impl cbor::Decode for TransactionWeight {
    fn try_from_cbor_value(value: cbor::Value) -> Result<Self, cbor::DecodeError> {
        match value {
            cbor::Value::TextString(v) if &v == "consensus_messages" => Ok(Self::ConsensusMessages),
            cbor::Value::TextString(other) => Ok(Self::Custom(other)),
            _ => Err(cbor::DecodeError::UnexpectedType),
        }
    }
}

#[derive(Clone, Copy, Debug, cbor::Encode, cbor::Decode)]
#[repr(u8)]
pub enum MessageType {
    /// Invalid message (should never be seen on the wire).
    Invalid = 0,
    /// Request.
    Request = 1,
    /// Response.
    Response = 2,
}

/// Runtime protocol message.
#[derive(Debug, cbor::Encode, cbor::Decode)]
pub struct Message {
    /// Unique request identifier.
    pub id: u64,
    /// Message type.
    pub message_type: MessageType,
    /// Message body.
    pub body: Body,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_consistent_check_tx_weight() {
        let tcs = vec![
            (
                "cmNvbnNlbnN1c19tZXNzYWdlcw==",
                TransactionWeight::ConsensusMessages,
            ),
            ("cmNvbnNlbnN1c19tZXNzYWdlcw==", "consensus_messages".into()),
            ("Y2dhcw==", "gas".into()),
        ];
        for (encoded_base64, rr) in tcs {
            let dec: TransactionWeight = cbor::from_slice(&base64::decode(encoded_base64).unwrap())
                .expect("TransactionWeight should deserialize correctly");
            assert_eq!(
                dec, rr,
                "decoded TransactionWeight should match the expected value"
            );
        }
    }
}
