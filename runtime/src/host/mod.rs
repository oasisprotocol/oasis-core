//! Host interface.
use async_trait::async_trait;
use thiserror::Error;

use crate::{
    common::{crypto::signature::PublicKey, namespace::Namespace},
    enclave_rpc,
    protocol::Protocol,
    storage::mkvs::sync,
    types::{self, Body},
};

pub mod attestation;
pub mod bundle_manager;
pub mod log_manager;
pub mod volume_manager;

/// Errors.
#[derive(Error, Debug)]
pub enum Error {
    #[error("bad response from host")]
    BadResponse,

    #[error("{0}")]
    Host(#[from] types::Error),

    #[error("{0}")]
    Decode(#[from] cbor::DecodeError),
}

/// Transaction submission options.
#[derive(Clone, Default, Debug)]
pub struct SubmitTxOpts {
    /// Target runtime identifier. If not specified, own runtime identifier is used.
    pub runtime_id: Option<Namespace>,
    /// Whether the call should wait until the transaction is included in a block.
    pub wait: bool,
    /// Whether the response should include a proof of transaction being included in a block.
    pub prove: bool,
}

/// Transaction submission result.
#[derive(Clone, Default, Debug)]
pub struct TxResult {
    /// Transaction output.
    pub output: Vec<u8>,
    /// Round in which the transaction was executed.
    pub round: u64,
    /// Order of the transaction in the execution batch.
    pub batch_order: u32,
    /// Optional inclusion proof.
    pub proof: Option<sync::Proof>,
}

/// Interface to the (untrusted) host node.
#[async_trait]
pub trait Host: Send + Sync {
    /// Returns the identity of the host node.
    async fn identity(&self) -> Result<PublicKey, Error>;

    /// Submit a transaction.
    async fn submit_tx(&self, data: Vec<u8>, opts: SubmitTxOpts)
        -> Result<Option<TxResult>, Error>;

    /// Bundle manager interface.
    fn bundle_manager(&self) -> &dyn bundle_manager::BundleManager;

    /// Volume manager interface.
    fn volume_manager(&self) -> &dyn volume_manager::VolumeManager;

    /// Log manager interface.
    fn log_manager(&self) -> &dyn log_manager::LogManager;

    /// Attestation interface.
    fn attestation(&self) -> &dyn attestation::Attestation;
}

#[async_trait]
impl Host for Protocol {
    async fn identity(&self) -> Result<PublicKey, Error> {
        match self.call_host_async(Body::HostIdentityRequest {}).await? {
            Body::HostIdentityResponse { node_id } => Ok(node_id),
            _ => Err(Error::BadResponse),
        }
    }

    async fn submit_tx(
        &self,
        data: Vec<u8>,
        opts: SubmitTxOpts,
    ) -> Result<Option<TxResult>, Error> {
        match self
            .call_host_async(Body::HostSubmitTxRequest {
                runtime_id: opts.runtime_id.unwrap_or_else(|| self.get_runtime_id()),
                data,
                wait: opts.wait,
                prove: opts.prove,
            })
            .await?
        {
            Body::HostSubmitTxResponse {
                output,
                round,
                batch_order,
                proof,
            } => {
                if opts.wait {
                    Ok(Some(TxResult {
                        output,
                        round,
                        batch_order,
                        proof,
                    }))
                } else {
                    // If we didn't wait for inclusion then there is no result.
                    Ok(None)
                }
            }
            _ => Err(Error::BadResponse),
        }
    }

    fn bundle_manager(&self) -> &dyn bundle_manager::BundleManager {
        self
    }

    fn volume_manager(&self) -> &dyn volume_manager::VolumeManager {
        self
    }

    fn log_manager(&self) -> &dyn log_manager::LogManager {
        self
    }

    fn attestation(&self) -> &dyn attestation::Attestation {
        self
    }
}

/// Wrapper to call the host via local RPC.
pub(super) async fn host_rpc_call<Rq: cbor::Encode, Rs: cbor::Decode>(
    protocol: &Protocol,
    endpoint: &str,
    method: &str,
    args: Rq,
) -> Result<Rs, Error> {
    match protocol
        .call_host_async(Body::HostRPCCallRequest {
            endpoint: endpoint.to_string(),
            request_id: 0,
            request: cbor::to_vec(enclave_rpc::types::Request {
                method: method.to_string(),
                args: cbor::to_value(args),
            }),
            kind: enclave_rpc::types::Kind::LocalQuery,
            nodes: vec![],
        })
        .await?
    {
        Body::HostRPCCallResponse { response, .. } => Ok(cbor::from_slice(&response)?),
        _ => Err(Error::BadResponse),
    }
}
