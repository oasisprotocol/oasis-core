//! Enclave RPC interface.
use serde_cbor;
use sgx_types::*;

use ekiden_common::error::{Error, Result};
use ekiden_enclave_untrusted::Enclave;
use ekiden_rpc_common::api;

use super::ecall_proxy;

pub trait EnclaveRpc {
    /// Maximum response size (in kilobytes).
    const MAX_RESPONSE_SIZE: usize = 1024;

    /// Perform a RPC call against the enclave.
    fn call(&self, request: api::EnclaveRequest) -> Result<api::EnclaveResponse>;
}

impl EnclaveRpc for Enclave {
    /// Perform a RPC call against the enclave.
    fn call(&self, request: api::EnclaveRequest) -> Result<api::EnclaveResponse> {
        // Encode request.
        let mut request = serde_cbor::to_vec(&request)?;

        // Reserve space up to the maximum size of serialized response.
        // TODO: Can we avoid allocating large response buffers each time?
        let mut response: Vec<u8> = Vec::with_capacity(Self::MAX_RESPONSE_SIZE * 1024);

        // Ensure that request is actually allocated as the length of the actual request
        // may be zero and in that case the OCALL will fail with SGX_ERROR_INVALID_PARAMETER.
        request.reserve(1);

        let mut response_length = 0;
        let status = unsafe {
            ecall_proxy::rpc_call(
                self.get_id(),
                request.as_ptr() as *const u8,
                request.len(),
                response.as_mut_ptr() as *mut u8,
                response.capacity(),
                &mut response_length,
            )
        };

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(Error::new("Failed to call enclave RPC"));
        }

        unsafe {
            response.set_len(response_length);
        }

        // Decode response.
        Ok(serde_cbor::from_slice(&response)?)
    }
}
