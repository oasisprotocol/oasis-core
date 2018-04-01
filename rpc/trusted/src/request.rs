//! RPC request type.
use std::ops::Deref;

use ekiden_enclave_common::quote::MrEnclave;

use super::error::DispatchError;

/// Wrapper for requests to provide additional request metadata.
#[derive(Debug, Clone)]
pub struct Request<T> {
    /// Underlying request message.
    message: Option<T>,
    /// Request method name.
    method: Option<String>,
    /// Client short-term public key (if request is authenticated).
    public_key: Option<Vec<u8>>,
    /// Client MRENCLAVE (if channel is mutually authenticated).
    mr_enclave: Option<MrEnclave>,
    /// Optional error occurred during request processing.
    error: Option<DispatchError>,
}

impl<T> Request<T> {
    /// Create new request wrapper from message.
    pub fn new(
        message: T,
        method: String,
        public_key: Option<Vec<u8>>,
        mr_enclave: Option<MrEnclave>,
    ) -> Self {
        Request {
            message: Some(message),
            method: Some(method),
            public_key: public_key,
            mr_enclave: mr_enclave,
            error: None,
        }
    }

    /// Create new request with dispatch error.
    pub fn error(error: DispatchError) -> Self {
        Request {
            message: None,
            method: None,
            public_key: None,
            mr_enclave: None,
            error: Some(error),
        }
    }

    /// Copy metadata of the current request into a new request object.
    ///
    /// This method can be used when extracting a part of a request data (e.g. the
    /// payload) and the caller would like to keep the associated metadata. The
    /// metadata will be cloned and the given `message` will be wrapped into a
    /// [`Request`] object.
    ///
    /// [`Request`]: Request
    pub fn copy_metadata_to<M>(&self, message: M) -> Request<M> {
        Request {
            message: Some(message),
            method: self.method.clone(),
            public_key: self.public_key.clone(),
            mr_enclave: self.mr_enclave.clone(),
            error: None,
        }
    }

    /// Get short-term public key of the client making this request.
    ///
    /// If the request was made over a non-secure channel, this will be [`None`].
    ///
    /// [`None`]: std::option::Option
    pub fn get_client_public_key(&self) -> Option<&Vec<u8>> {
        self.public_key.as_ref()
    }

    /// Get MRENCLAVE of the client making this request.
    ///
    /// If the request was made over a channel without client attestation, this
    /// will be [`None`].
    ///
    /// [`None`]: std::option::Option
    pub fn get_client_mr_enclave(&self) -> Option<&MrEnclave> {
        self.mr_enclave.as_ref()
    }

    /// Get optional error if any occurred during dispatch.
    pub fn get_error(&self) -> Option<&DispatchError> {
        self.error.as_ref()
    }

    /// Get optional request method name.
    pub fn get_method(&self) -> Option<&String> {
        self.method.as_ref()
    }
}

impl<T> Deref for Request<T> {
    type Target = T;

    /// Dereferences the request into underlying message.
    ///
    /// If there is no message (e.g., due to request processing resulting in an
    /// erro), dereferencing will panic.
    fn deref(&self) -> &T {
        &self.message.as_ref().unwrap()
    }
}
