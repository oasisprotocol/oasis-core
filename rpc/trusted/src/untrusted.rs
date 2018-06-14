#[cfg(target_env = "sgx")]
use sgx_types::*;

#[cfg(target_env = "sgx")]
use protobuf::{self, Message};

use ekiden_common::error::{Error, Result};
use ekiden_rpc_common::client::ClientEndpoint;

/// OCALLs defined by the Ekiden enclave specification.
#[cfg(target_env = "sgx")]
extern "C" {
    /// Interface for outgoing RPC calls (to other enclaves or services).
    pub fn untrusted_rpc_call(
        endpoint: u16,
        request_data: *const u8,
        request_length: usize,
        response_data: *mut u8,
        response_capacity: usize,
        response_length: *mut usize,
    ) -> sgx_status_t;
}

/// Perform an untrusted RPC call against a given (untrusted) endpoint.
///
/// How the actual RPC call is implemented depends on the handler implemented
/// in the untrusted part.
#[cfg(target_env = "sgx")]
pub fn untrusted_call_endpoint<Rq, Rs>(endpoint: &ClientEndpoint, request: Rq) -> Result<Rs>
where
    Rq: Message,
    Rs: Message,
{
    Ok(protobuf::parse_from_bytes(&untrusted_call_endpoint_raw(
        &endpoint,
        request.write_to_bytes()?,
    )?)?)
}

#[cfg(not(target_env = "sgx"))]
pub fn untrusted_call_endpoint<Rq, Rs>(_endpoint: &ClientEndpoint, _request: Rq) -> Result<Rs> {
    Err(Error::new("Only supported in SGX builds"))
}

/// Perform a raw RPC call against a given (untrusted) endpoint.
///
/// How the actual RPC call is implemented depends on the handler implemented
/// in the untrusted part.
#[cfg(target_env = "sgx")]
pub fn untrusted_call_endpoint_raw(
    endpoint: &ClientEndpoint,
    mut request: Vec<u8>,
) -> Result<Vec<u8>> {
    // Maximum size of serialized response is 64K.
    let mut response: Vec<u8> = Vec::with_capacity(64 * 1024);

    // Ensure that request is actually allocated as the length of the actual request
    // may be zero and in that case the OCALL will fail with SGX_ERROR_INVALID_PARAMETER.
    request.reserve(1);

    let mut response_length = 0;
    let status = unsafe {
        untrusted_rpc_call(
            endpoint.as_u16(),
            request.as_ptr() as *const u8,
            request.len(),
            response.as_mut_ptr() as *mut u8,
            response.capacity(),
            &mut response_length,
        )
    };

    match status {
        sgx_status_t::SGX_SUCCESS => {}
        status => {
            return Err(Error::new(format!(
                "Enclave RPC OCALL failed: {:?}",
                status
            )));
        }
    }

    unsafe {
        response.set_len(response_length);
    }

    Ok(response)
}

#[cfg(not(target_env = "sgx"))]
pub fn untrusted_call_endpoint_raw(
    _endpoint: &ClientEndpoint,
    _request: Vec<u8>,
) -> Result<Vec<u8>> {
    Err(Error::new("Only supported in SGX builds"))
}
