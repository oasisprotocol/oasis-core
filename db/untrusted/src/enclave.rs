//! Enclave database interface.
use std::cell::RefCell;
use std::sync::Arc;

use sgx_types::*;

use ekiden_common::bytes::H256;
use ekiden_common::error::{Error, Result};
use ekiden_enclave_untrusted::Enclave;
use ekiden_storage_base::StorageBackend;

use super::ecall_proxy;

thread_local! {
    /// Current storage backend.
    ///
    /// This will only be set when the current thread is running in a `with_storage` context
    /// and will otherwise be `None`.
    static STORAGE: RefCell<Option<Arc<StorageBackend>>> = RefCell::new(None);

    /// Transfer buffer for storage OCALLs.
    static TRANSFER_BUFFER: RefCell<Vec<u8>> = RefCell::new(vec![0; 8 * 1024 * 1024]);
}

struct WithStorageGuard;

impl WithStorageGuard {
    fn new(backend: Arc<StorageBackend>) -> Self {
        STORAGE.with(|storage| {
            // Set current storage.
            assert!(
                storage.borrow().is_none(),
                "storage backend set multiple times"
            );
            *storage.borrow_mut() = Some(backend);
        });

        WithStorageGuard
    }
}

impl Drop for WithStorageGuard {
    fn drop(&mut self) {
        STORAGE.with(|storage| {
            // Clear storage when the guard is dropped.
            *storage.borrow_mut() = None;
        });
    }
}

/// Enclave database interface.
pub trait EnclaveDb {
    /// Execute enclave operations with the given storage backend.
    ///
    /// A reference to the storage backend is stored in thread-local storage so any OCALLs
    /// from the enclave will use the specified backend.
    ///
    /// Before invoking the closure, the root hash is communicated to the enclave. After
    /// invoking the closure, the new root hash is fetched from the enclave.
    ///
    /// Use [`current_storage`] to get the storage backend in OCALLs.
    fn with_storage<F: FnOnce() -> R, R>(
        &self,
        storage: Arc<StorageBackend>,
        root_hash: &H256,
        f: F,
    ) -> Result<(H256, R)>;
}

impl EnclaveDb for Enclave {
    fn with_storage<F: FnOnce() -> R, R>(
        &self,
        storage: Arc<StorageBackend>,
        root_hash: &H256,
        f: F,
    ) -> Result<(H256, R)> {
        // Construct a guard so storage is properly cleared in case of unwinds.
        let _guard = WithStorageGuard::new(storage);

        // Ensure transfer buffer is configured.
        TRANSFER_BUFFER.with(|buffer| {
            let mut buffer = buffer.borrow_mut();
            let status = unsafe {
                ecall_proxy::db_set_transfer_buffer(
                    self.get_id(),
                    buffer.as_mut_ptr() as *mut u8,
                    buffer.len(),
                )
            };
            if status != sgx_status_t::SGX_SUCCESS {
                return Err(Error::new("failed to configure storage transfer buffer"));
            }

            Ok(())
        })?;

        // Notify enclave what the latest state's root hash is.
        let status = unsafe {
            ecall_proxy::db_set_root_hash(self.get_id(), root_hash.as_ptr() as *const u8)
        };
        if status != sgx_status_t::SGX_SUCCESS {
            return Err(Error::new("failed to notify enclave of state root hash"));
        }

        // Invoke code that may call enclave methods.
        let result = f();

        // Get the new state root hash.
        let mut root_hash = H256::zero();

        let status =
            unsafe { ecall_proxy::db_commit(self.get_id(), root_hash.as_mut_ptr() as *mut u8) };
        if status != sgx_status_t::SGX_SUCCESS {
            return Err(Error::new("failed to get new state root hash from enclave"));
        }

        Ok((root_hash, result))
    }
}

/// Return the current storage backend.
///
/// This method can only be called inside a `with_storage` context.
///
/// # Panics
///
/// If called outside the `with_storage` context, this function will panic.
pub fn current_storage() -> Arc<StorageBackend> {
    STORAGE.with(|storage| {
        let storage_ref = storage.borrow();
        let storage = storage_ref
            .as_ref()
            .expect("current_storage called outside with_storage context");
        storage.clone()
    })
}

/// Run a closure with the current transfer buffer as argument.
pub fn with_transfer_buffer<F: FnOnce(&mut [u8]) -> R, R>(f: F) -> R {
    TRANSFER_BUFFER.with(|buffer| {
        let mut buffer_ref = buffer.borrow_mut();
        f(&mut buffer_ref)
    })
}
