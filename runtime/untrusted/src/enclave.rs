//! Enclave async runtime interface.
use serde_cbor;
use sgx_types::*;

use ekiden_common::error::{Error, Result};
use ekiden_enclave_untrusted::Enclave;
use ekiden_roothash_base::Header;
use ekiden_runtime_common::batch::{CallBatch, OutputBatch};

use super::ecall_proxy;

pub trait EnclaveRuntime {
    /// Maximum response size (in kilobytes).
    const MAX_RESPONSE_SIZE: usize = 16 * 1024;

    /// Invoke a runtime on a batch of calls and return the (encrypted) outputs.
    fn runtime_call_batch(&self, batch: &CallBatch, header: &Header) -> Result<OutputBatch>;
}

impl EnclaveRuntime for Enclave {
    fn runtime_call_batch(&self, batch: &CallBatch, header: &Header) -> Result<OutputBatch> {
        // Encode input batch.
        let batch_encoded = serde_cbor::to_vec(batch)?;

        // Encode block header.
        let header_encoded = serde_cbor::to_vec(header)?;

        // Reserve space up to the maximum size of serialized response.
        let mut response: Vec<u8> = Vec::with_capacity(Self::MAX_RESPONSE_SIZE * 1024);
        let mut response_length = 0;

        let status = unsafe {
            ecall_proxy::runtime_call_batch(
                self.get_id(),
                batch_encoded.as_ptr() as *const u8,
                batch_encoded.len(),
                header_encoded.as_ptr() as *const u8,
                header_encoded.len(),
                response.as_mut_ptr() as *mut u8,
                response.capacity(),
                &mut response_length,
            )
        };

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(Error::new(format!(
                "runtime_call_batch: failed to call enclave ({})",
                status
            )));
        }

        unsafe {
            response.set_len(response_length);
        }

        let outputs: OutputBatch = serde_cbor::from_slice(&response)?;

        // Assert equal number of responses, fail otherwise (corrupted response).
        if outputs.len() != batch.len() {
            return Err(Error::new(
                "runtime_call_batch: corrupted response (response count != request count)",
            ));
        }

        Ok(outputs)
    }
}
