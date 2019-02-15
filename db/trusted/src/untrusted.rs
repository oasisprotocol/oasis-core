//! Storage backend that talks to an external backend outside the enclave.
use std::{slice::from_raw_parts_mut, sync::SgxMutex as Mutex};

use sgx_trts::{libc::c_void, trts::rsgx_raw_is_outside_enclave};
use sgx_types::*;
use sgx_unwind;

use ekiden_common::{
    bytes::H256,
    error::Error,
    futures::{future, BoxFuture, BoxStream},
};
use ekiden_storage_base::{hash_storage_key, InsertOptions, StorageBackend};

/// OCALLs defined by the Ekiden enclave specification.
extern "C" {
    fn untrusted_db_get(key: *const u8, value_length: *mut usize, result: *mut u8) -> sgx_status_t;

    fn untrusted_db_insert(value_length: usize, expiry: u64, result: *mut u8) -> sgx_status_t;
}

lazy_static! {
    // Untrusted transfer buffer for OCALLs.
    static ref UNTRUSTED_TRANSFER_BUFFER: Mutex<Option<&'static mut [u8]>> = Mutex::new(None);
}

/// Storage backend that talks to an external backend outside the enclave.
pub struct UntrustedStorageBackend;

impl UntrustedStorageBackend {
    pub fn new() -> Self {
        Self {}
    }
}

const FRAMES_CAPACITY: usize = 5;

struct StoragestudyCookie {
    frames: [*mut c_void; FRAMES_CAPACITY],
    size: usize,
}

extern "C" fn storagestudy_trace(
    ctx: *mut sgx_unwind::_Unwind_Context,
    arg: *mut c_void,
) -> sgx_unwind::_Unwind_Reason_Code {
    let cookie = unsafe { (arg as *mut StoragestudyCookie).as_mut() }.unwrap();
    if cookie.size >= FRAMES_CAPACITY {
        return sgx_unwind::_URC_NORMAL_STOP;
    }

    // logic taken from rust-sgx-sdk sgx_tstd sys backtrace tracing gcc_s
    let mut ip_before_insn = 0;
    let mut ip = unsafe { sgx_unwind::_Unwind_GetIPInfo(ctx, &mut ip_before_insn) } as *mut c_void;
    if !ip.is_null() && ip_before_insn == 0 {
        ip = (ip as usize - 1) as *mut c_void;
    }

    cookie.frames[cookie.size] = ip;
    cookie.size += 1;

    sgx_unwind::_URC_NO_REASON
}

fn storagestudy_dump(message: &str) {
    let mut cookie = StoragestudyCookie {
        frames: [std::ptr::null_mut(); FRAMES_CAPACITY],
        size: 0,
    };
    let rv = unsafe {
        sgx_unwind::_Unwind_Backtrace(
            storagestudy_trace,
            &mut cookie as *mut StoragestudyCookie as *mut c_void,
        )
    };
    match rv {
        sgx_unwind::_URC_END_OF_STACK | sgx_unwind::_URC_FATAL_PHASE1_ERROR => {
            println!("{} at {:?}", message, &cookie.frames[..cookie.size]);
        }
        other => {
            println!("{} backtrace error {:?}", message, other);
        }
    }
}

impl StorageBackend for UntrustedStorageBackend {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        panic!("%%% storage get")
        storagestudy_dump("%%% storage get");
        Box::new(future::lazy(move || {
            let mut value_length = 0;
            let mut result = 1;

            let status = unsafe {
                untrusted_db_get(key.as_ptr() as *const u8, &mut value_length, &mut result)
            };
            if status != sgx_status_t::SGX_SUCCESS {
                return Err(Error::new(format!(
                    "failed to fetch value from storage ({})",
                    status
                )));
            }
            if result != 0 {
                return Err(Error::new("failed to fetch value from storage"));
            }

            // Load data from untrusted transfer buffer.
            let buffer_guard = UNTRUSTED_TRANSFER_BUFFER.lock().unwrap();
            let buffer = buffer_guard
                .as_ref()
                .expect("transfer buffer not configured");

            // Check that the hash matches the key.
            let data = buffer[..value_length].to_vec();
            if hash_storage_key(&data) != key {
                return Err(Error::new("incorrect value returned from storage"));
            }

            Ok(data)
        }))
    }

    fn get_batch(&self, _keys: Vec<H256>) -> BoxFuture<Vec<Option<Vec<u8>>>> {
        unimplemented!();
    }

    fn insert(&self, value: Vec<u8>, expiry: u64, _opts: InsertOptions) -> BoxFuture<()> {
        panic!("%%% storage set")
        storagestudy_dump("%%% storage set");
        Box::new(future::lazy(move || {
            // Copy value into untrusted transfer buffer.
            {
                let mut buffer_guard = UNTRUSTED_TRANSFER_BUFFER.lock().unwrap();
                let buffer = buffer_guard
                    .as_mut()
                    .expect("transfer buffer not configured");

                buffer[..value.len()].clone_from_slice(&value);
            }

            let mut result = 1;
            let status = unsafe { untrusted_db_insert(value.len(), expiry, &mut result) };
            if status != sgx_status_t::SGX_SUCCESS {
                return Err(Error::new(format!(
                    "failed to insert value to storage ({})",
                    status
                )));
            }
            if result != 0 {
                return Err(Error::new("failed to insert value to storage"));
            }

            Ok(())
        }))
    }

    fn insert_batch(&self, _values: Vec<(Vec<u8>, u64)>, _opts: InsertOptions) -> BoxFuture<()> {
        unimplemented!();
    }

    fn get_keys(&self) -> BoxStream<(H256, u64)> {
        unimplemented!();
    }
}

/// Setup transfer buffer used for OCALLs to untrusted storage backend.
#[no_mangle]
pub extern "C" fn db_set_transfer_buffer(buffer: *mut u8, buffer_capacity: usize) {
    if buffer.is_null() {
        panic!("Transfer buffer must not be null");
    }

    if buffer_capacity < 10240 {
        panic!("Transfer buffer too small");
    }

    // Ensure that transfer buffer is in untrusted memory. This is required because
    // we are using user_check in the EDL so we must do all checks manually. If
    // the pointer was inside the enclave, we could expose arbitrary parts of
    // enclave memory.
    if !rsgx_raw_is_outside_enclave(buffer, buffer_capacity) {
        panic!("Security violation: transfer buffer must be in untrusted memory");
    }

    let mut transfer_buffer = UNTRUSTED_TRANSFER_BUFFER.lock().unwrap();
    *transfer_buffer = Some(unsafe { from_raw_parts_mut(buffer, buffer_capacity) });
}
