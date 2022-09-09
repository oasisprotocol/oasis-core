//! Host interface.
use io_context::Context;
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
pub trait Host: Send + Sync {
    /// Returns the identity of the host node.
    fn identity(&self) -> Result<PublicKey, Error>;
}

impl Host for Protocol {
    fn identity(&self) -> Result<PublicKey, Error> {
        match self.call_host(Context::background(), Body::HostIdentityRequest {})? {
            Body::HostIdentityResponse { node_id } => Ok(node_id),
            _ => Err(Error::BadResponse),
        }
    }
}
