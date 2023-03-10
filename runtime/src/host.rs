//! Host interface.
use async_trait::async_trait;
use thiserror::Error;

use crate::{
    common::crypto::signature::PublicKey,
    protocol::Protocol,
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

/// Interface to the (untrusted) host node.
#[async_trait]
pub trait Host: Send + Sync {
    /// Returns the identity of the host node.
    async fn identity(&self) -> Result<PublicKey, Error>;
}

#[async_trait]
impl Host for Protocol {
    async fn identity(&self) -> Result<PublicKey, Error> {
        match self.call_host_async(Body::HostIdentityRequest {}).await? {
            Body::HostIdentityResponse { node_id } => Ok(node_id),
            _ => Err(Error::BadResponse),
        }
    }
}
