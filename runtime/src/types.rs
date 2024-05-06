//! Types used by the worker-host protocol.
use std::collections::BTreeMap;

use thiserror::Error;

use crate::{
    common::{
        crypto::{
            hash::Hash,
            signature::{self, Signature},
            x25519,
        },
        namespace::Namespace,
        sgx::{ias::AVR, Quote, QuotePolicy},
        version::Version,
    },
    consensus::{
        self,
        beacon::EpochTime,
        registry::EndorsedCapabilityTEE,
        roothash::{self, Block, ComputeResultsHeader, Header},
        state::keymanager::Status as KeyManagerStatus,
        transaction::{Proof, SignedTransaction},
        LightBlock,
    },
    enclave_rpc,
    storage::mkvs::{sync, WriteLog},
    transaction::types::TxnBatch,
};

/// Computed batch.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
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
        rak_pub: signature::PublicKey,
        rek_pub: x25519::PublicKey,
        report: Vec<u8>,
        nonce: String,
    },
    RuntimeCapabilityTEERakAvrRequest {
        avr: AVR,
    },
    RuntimeCapabilityTEERakAvrResponse {},
    RuntimeCapabilityTEERakQuoteRequest {
        quote: Quote,
    },
    RuntimeCapabilityTEERakQuoteResponse {
        height: u64,
        signature: Signature,
    },
    RuntimeCapabilityTEEUpdateEndorsementRequest {
        ect: EndorsedCapabilityTEE,
    },
    RuntimeCapabilityTEEUpdateEndorsementResponse {},
    RuntimeRPCCallRequest {
        request: Vec<u8>,
        kind: enclave_rpc::types::Kind,
        peer_id: Vec<u8>,
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
        #[cbor(optional)]
        mode: ExecutionMode,
        consensus_block: LightBlock,
        round_results: roothash::RoundResults,
        io_root: Hash,
        #[cbor(optional)]
        inputs: Option<TxnBatch>,
        #[cbor(optional)]
        in_msgs: Vec<roothash::IncomingMessage>,
        block: Block,
        epoch: EpochTime,
        max_messages: u32,
    },
    RuntimeExecuteTxBatchResponse {
        batch: ComputedBatch,

        tx_hashes: Vec<Hash>,
        tx_reject_hashes: Vec<Hash>,
        tx_input_root: Hash,
        tx_input_write_log: WriteLog,
    },
    RuntimeKeyManagerStatusUpdateRequest {
        status: KeyManagerStatus,
    },
    RuntimeKeyManagerStatusUpdateResponse {},
    RuntimeKeyManagerQuotePolicyUpdateRequest {
        policy: QuotePolicy,
    },
    RuntimeKeyManagerQuotePolicyUpdateResponse {},
    RuntimeQueryRequest {
        consensus_block: LightBlock,
        header: Header,
        epoch: EpochTime,
        max_messages: u32,
        method: String,
        #[cbor(optional)]
        args: Vec<u8>,
    },
    RuntimeQueryResponse {
        #[cbor(optional)]
        data: Vec<u8>,
    },
    RuntimeConsensusSyncRequest {
        height: u64,
    },
    RuntimeConsensusSyncResponse {},
    RuntimeNotifyRequest {
        #[cbor(optional)]
        runtime_block: Option<roothash::AnnotatedBlock>,
        #[cbor(optional)]
        runtime_event: Option<RuntimeNotifyEvent>,
    },
    RuntimeNotifyResponse {},

    // Host interface.
    HostRPCCallRequest {
        endpoint: String,
        request: Vec<u8>,
        kind: enclave_rpc::types::Kind,
        nodes: Vec<signature::PublicKey>,
        #[cbor(optional, rename = "pf")]
        peer_feedback: Option<enclave_rpc::types::PeerFeedback>,
    },
    HostRPCCallResponse {
        response: Vec<u8>,
        node: signature::PublicKey,
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
    HostFetchConsensusEventsRequest(HostFetchConsensusEventsRequest),
    HostFetchConsensusEventsResponse(HostFetchConsensusEventsResponse),
    HostFetchTxBatchRequest {
        #[cbor(optional)]
        offset: Option<Hash>,
        limit: u32,
    },
    HostFetchTxBatchResponse {
        #[cbor(optional)]
        batch: Option<TxnBatch>,
    },
    HostFetchBlockMetadataTxRequest {
        height: u64,
    },
    HostFetchBlockMetadataTxResponse {
        signed_tx: SignedTransaction,
        proof: Proof,
    },
    HostFetchGenesisHeightRequest {},
    HostFetchGenesisHeightResponse {
        height: u64,
    },
    HostProveFreshnessRequest {
        blob: Vec<u8>,
    },
    HostProveFreshnessResponse {
        signed_tx: SignedTransaction,
        proof: Proof,
    },
    HostIdentityRequest {},
    HostIdentityResponse {
        node_id: signature::PublicKey,
    },
    HostSubmitTxRequest {
        runtime_id: Namespace,
        data: Vec<u8>,
        wait: bool,
        prove: bool,
    },
    HostSubmitTxResponse {
        output: Vec<u8>,
        round: u64,
        batch_order: u32,
        proof: Option<sync::Proof>,
    },
    HostRegisterNotifyRequest {
        #[cbor(optional)]
        runtime_block: bool,
        #[cbor(optional)]
        runtime_event: Option<RegisterNotifyRuntimeEvent>,
    },
    HostRegisterNotifyResponse {},
}

impl Default for Body {
    fn default() -> Self {
        Self::Empty {}
    }
}

/// A serializable error.
#[derive(Clone, Debug, Default, Error, cbor::Encode, cbor::Decode)]
#[error("module: {module} code: {code} message: {message}")]
pub struct Error {
    #[cbor(optional)]
    pub module: String,

    #[cbor(optional)]
    pub code: u32,

    #[cbor(optional)]
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
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct RuntimeInfoRequest {
    pub runtime_id: Namespace,
    pub consensus_backend: String,
    pub consensus_protocol_version: Version,
    pub consensus_chain_context: String,

    #[cbor(optional)]
    pub local_config: BTreeMap<String, cbor::Value>,
}

/// Set of supported runtime features.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
pub struct Features {
    /// Schedule control feature.
    #[cbor(optional)]
    pub schedule_control: Option<FeatureScheduleControl>,
    /// A feature specifying that the runtime supports updating key manager's quote policy.
    #[cbor(optional)]
    pub key_manager_quote_policy_updates: bool,
    /// A feature specifying that the runtime supports updating key manager's status.
    #[cbor(optional)]
    pub key_manager_status_updates: bool,
    /// A feature specifying that the runtime supports RPC peer IDs.
    #[cbor(optional)]
    pub rpc_peer_id: bool,
    /// A feature specifying that the runtime supports endorsed TEE capabilities.
    #[cbor(optional)]
    pub endorsed_capability_tee: bool,
}

impl Default for Features {
    fn default() -> Self {
        Self {
            schedule_control: None,
            key_manager_quote_policy_updates: true,
            key_manager_status_updates: true,
            rpc_peer_id: true,
            endorsed_capability_tee: true,
        }
    }
}

/// A feature specifying that the runtime supports controlling the scheduling of batches. This means
/// that the scheduler should only take priority into account and ignore weights, leaving it up to
/// the runtime to decide which transactions to include.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct FeatureScheduleControl {
    /// Size of the initial batch of transactions.
    pub initial_batch_size: u32,
}

/// Runtime information response.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct RuntimeInfoResponse {
    /// The runtime protocol version supported by the runtime.
    pub protocol_version: Version,

    /// The version of the runtime.
    pub runtime_version: Version,

    /// Describes the features supported by the runtime.
    pub features: Features,
}

/// Batch execution mode.
#[derive(Clone, Debug, PartialEq, Eq, cbor::Encode, cbor::Decode)]
#[cbor(with_default)]
pub enum ExecutionMode {
    /// Execution mode where the batch of transactions is executed as-is without the ability to
    /// perform and modifications to the batch.
    Execute = 0,
    /// Execution mode where the runtime is in control of scheduling and may arbitrarily modify the
    /// batch during execution.
    ///
    /// This execution mode will only be used in case the runtime advertises to support the schedule
    /// control feature. In this case the call will only contain up to InitialBatchSize transactions
    /// and the runtime will need to request more if it needs more.
    Schedule = 1,
}

impl Default for ExecutionMode {
    fn default() -> Self {
        Self::Execute
    }
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
    pub priority: u64,

    #[cbor(optional)]
    pub sender: Vec<u8>,
    #[cbor(optional)]
    pub sender_seq: u64,
    #[cbor(optional)]
    pub sender_state_seq: u64,
}

/// Consensus event kind.
#[derive(Clone, Copy, Debug, cbor::Encode, cbor::Decode)]
#[repr(u8)]
pub enum EventKind {
    Staking = 1,
    Registry = 2,
    RootHash = 3,
    Governance = 4,
}

/// Request to host to fetch the consensus events for the given height.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
#[cbor(no_default)]
pub struct HostFetchConsensusEventsRequest {
    pub height: u64,
    pub kind: EventKind,
}

/// Response from host fetching the consensus events for the given height.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct HostFetchConsensusEventsResponse {
    pub events: Vec<consensus::Event>,
}

/// Registration for runtime event notifications.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct RegisterNotifyRuntimeEvent {
    /// Event tags to subscribe to.
    pub tags: Vec<Vec<u8>>,
}

/// An event notification.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct RuntimeNotifyEvent {
    /// Header of the block that emitted the event.
    pub block: roothash::AnnotatedBlock,
    /// Matching tags.
    pub tags: Vec<Vec<u8>>,
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

impl Default for MessageType {
    fn default() -> Self {
        Self::Invalid
    }
}

/// Runtime protocol message.
#[derive(Debug, Default, cbor::Encode, cbor::Decode)]
pub struct Message {
    /// Unique request identifier.
    pub id: u64,
    /// Message type.
    pub message_type: MessageType,
    /// Message body.
    pub body: Body,
}
