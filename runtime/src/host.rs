//! Host interface.
use async_trait::async_trait;
use thiserror::Error;

use crate::{
    common::{crypto::signature::PublicKey, namespace::Namespace},
    protocol::Protocol,
    storage::mkvs::sync,
    types::{self, Body},
};

/// Errors.
#[derive(Error, Debug)]
pub enum Error {
    #[error("bad response from host")]
    BadResponse,
    #[error("{0}")]
    Other(#[from] types::Error),
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

/// Notification registration options.
#[derive(Clone, Default, Debug)]
pub struct RegisterNotifyOpts {
    /// Subscribe to runtime block notifications.
    pub runtime_block: bool,
    /// Subscribe to runtime event notifications.
    pub runtime_event: Vec<Vec<u8>>,
}

/// Interface to the (untrusted) host node.
#[async_trait]
pub trait Host: Send + Sync {
    /// Returns the identity of the host node.
    async fn identity(&self) -> Result<PublicKey, Error>;

    /// Submit a transaction.
    async fn submit_tx(&self, data: Vec<u8>, opts: SubmitTxOpts)
        -> Result<Option<TxResult>, Error>;

    /// Register for receiving notifications.
    async fn register_notify(&self, opts: RegisterNotifyOpts) -> Result<(), Error>;
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

    async fn register_notify(&self, opts: RegisterNotifyOpts) -> Result<(), Error> {
        match self
            .call_host_async(Body::HostRegisterNotifyRequest {
                runtime_block: opts.runtime_block,
                runtime_event: match opts.runtime_event {
                    tags if tags.is_empty() => None,
                    tags => Some(types::RegisterNotifyRuntimeEvent { tags }),
                },
            })
            .await?
        {
            Body::Empty {} => Ok(()),
            _ => Err(Error::BadResponse),
        }
    }
}
