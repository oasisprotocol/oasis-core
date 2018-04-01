//! Enclave RPC interface.
use sgx_types::*;

use protobuf;
use protobuf::{Message, MessageStatic, RepeatedField};

use ekiden_common::error::{Error, Result};
use ekiden_enclave_untrusted::Enclave;
use ekiden_rpc_common::api;

use super::ecall_proxy;

pub trait EnclaveRpc {
    /// Maximum response size (in kilobytes).
    const MAX_RESPONSE_SIZE: usize = 1024;

    /// Perform a plain-text RPC call against the enclave.
    fn call<R: Message, S: Message + MessageStatic>(&self, method: &str, request: &R) -> Result<S>;

    /// Perform a raw RPC call against the enclave.
    fn call_raw(&self, request: Vec<u8>) -> Result<Vec<u8>>;
}

impl EnclaveRpc for Enclave {
    /// Perform a plain-text RPC call against the enclave with no state.
    fn call<R: Message, S: Message + MessageStatic>(&self, method: &str, request: &R) -> Result<S> {
        // Prepare plain request.
        let mut plain_request = api::PlainClientRequest::new();
        plain_request.set_method(String::from(method));
        plain_request.set_payload(request.write_to_bytes()?);

        let mut client_request = api::ClientRequest::new();
        client_request.set_plain_request(plain_request);

        let mut enclave_request = api::EnclaveRequest::new();
        enclave_request.set_client_request(RepeatedField::from_slice(&[client_request]));

        let enclave_request_bytes = enclave_request.write_to_bytes()?;
        let enclave_response_bytes = self.call_raw(enclave_request_bytes)?;

        let enclave_response: api::EnclaveResponse =
            match protobuf::parse_from_bytes(enclave_response_bytes.as_slice()) {
                Ok(enclave_response) => enclave_response,
                _ => return Err(Error::new("Response parse error")),
            };

        let client_response = &enclave_response.get_client_response()[0];

        // Plain request requires a plain response.
        assert!(client_response.has_plain_response());
        let plain_response = client_response.get_plain_response();

        // Validate response code.
        match plain_response.get_code() {
            api::PlainClientResponse_Code::SUCCESS => {}
            _ => {
                // Deserialize error.
                let error: api::Error =
                    match protobuf::parse_from_bytes(plain_response.get_payload()) {
                        Ok(error) => error,
                        _ => return Err(Error::new("Unable to parse error payload")),
                    };

                return Err(Error::new(error.get_message()));
            }
        };

        // Deserialize response.
        match protobuf::parse_from_bytes(plain_response.get_payload()) {
            Ok(response) => Ok(response),
            _ => Err(Error::new("Unable to parse response payload")),
        }
    }

    /// Perform a raw RPC call against the enclave.
    fn call_raw(&self, mut request: Vec<u8>) -> Result<Vec<u8>> {
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

        Ok(response)
    }
}
