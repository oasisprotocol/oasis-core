//! Enclave database interface.
use sgx_types::*;

use ekiden_common::error::{Error, Result};
use ekiden_enclave_untrusted::Enclave;

use super::ecall_proxy;

/// Enclave database interface.
pub trait EnclaveDb {
    /// Maximum response size (in kilobytes).
    const MAX_RESPONSE_SIZE: usize = 1024;

    /// Compute difference between states.
    fn db_state_diff(&self, old: &Vec<u8>, new: &Vec<u8>) -> Result<Vec<u8>>;

    /// Apply difference between states to an existing state.
    fn db_state_apply(&self, old: &Vec<u8>, diff: &Vec<u8>) -> Result<Vec<u8>>;

    /// Set enclave state.
    fn db_state_set(&self, state: &Vec<u8>) -> Result<()>;

    /// Retrieve enclave state.
    ///
    /// If nothing was modified since the last import, this method will return an empty
    /// vector.
    fn db_state_get(&self) -> Result<Vec<u8>>;
}

impl EnclaveDb for Enclave {
    /// Compute difference between states.
    fn db_state_diff(&self, old: &Vec<u8>, new: &Vec<u8>) -> Result<Vec<u8>> {
        // Reserve space up to the maximum size of serialized response.
        let mut diff: Vec<u8> = Vec::with_capacity(Self::MAX_RESPONSE_SIZE * 1024);
        let mut diff_length = 0;

        let status = unsafe {
            ecall_proxy::db_state_diff(
                self.get_id(),
                old.as_ptr() as *const u8,
                old.len(),
                new.as_ptr() as *const u8,
                new.len(),
                diff.as_mut_ptr() as *mut u8,
                diff.capacity(),
                &mut diff_length,
            )
        };

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(Error::new("Failed to call enclave state diff"));
        }

        unsafe {
            diff.set_len(diff_length);
        }

        Ok(diff)
    }

    /// Apply difference between states to an existing state.
    fn db_state_apply(&self, old: &Vec<u8>, diff: &Vec<u8>) -> Result<Vec<u8>> {
        // Reserve space up to the maximum size of serialized response.
        let mut new: Vec<u8> = Vec::with_capacity(Self::MAX_RESPONSE_SIZE * 1024);
        let mut new_length = 0;

        let status = unsafe {
            ecall_proxy::db_state_apply(
                self.get_id(),
                old.as_ptr() as *const u8,
                old.len(),
                diff.as_ptr() as *const u8,
                diff.len(),
                new.as_mut_ptr() as *mut u8,
                new.capacity(),
                &mut new_length,
            )
        };

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(Error::new("Failed to call enclave state apply"));
        }

        unsafe {
            new.set_len(new_length);
        }

        Ok(new)
    }

    /// Set enclave state.
    fn db_state_set(&self, state: &Vec<u8>) -> Result<()> {
        let status = unsafe {
            ecall_proxy::db_state_set(self.get_id(), state.as_ptr() as *const u8, state.len())
        };

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(Error::new("Failed to call enclave state set"));
        }

        Ok(())
    }

    /// Retrieve enclave state.
    fn db_state_get(&self) -> Result<Vec<u8>> {
        // Reserve space up to the maximum size of serialized response.
        let mut state: Vec<u8> = Vec::with_capacity(Self::MAX_RESPONSE_SIZE * 1024);
        let mut state_length = 0;

        let status = unsafe {
            ecall_proxy::db_state_get(
                self.get_id(),
                state.as_mut_ptr() as *mut u8,
                state.capacity(),
                &mut state_length,
            )
        };

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(Error::new("Failed to call enclave state get"));
        }

        unsafe {
            state.set_len(state_length);
        }

        Ok(state)
    }
}
