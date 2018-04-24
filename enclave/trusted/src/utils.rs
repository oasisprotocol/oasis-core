//! Enclave utilities.
use std::io::Cursor;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use serde::{Deserialize, Serialize};
use serde_cbor;
#[cfg(target_env = "sgx")]
use sgx_trts::trts::rsgx_raw_is_outside_enclave;

/// Deserialize request buffer from untrusted memory.
///
/// # EDL
///
/// In order for this function to work, the source buffer must be declared using
/// the `[user_check]` attribute in the EDL.
///
/// # Panics
///
/// This function will panic if the source buffer is null or not in untrusted memory
/// as this may compromise enclave security. Failing to deserialize the request
/// buffer will also cause a panic.
pub fn read_enclave_request<'a, R>(src: *const u8, src_length: usize) -> R
where
    R: Deserialize<'a>,
{
    if src.is_null() {
        panic!("Source buffer must not be null");
    }

    // Ensure that request data is in untrusted memory. This is required because
    // we are using user_check in the EDL so we must do all checks manually. If
    // the pointer was inside the enclave, we could expose arbitrary parts of
    // enclave memory.
    #[cfg(target_env = "sgx")]
    {
        if !rsgx_raw_is_outside_enclave(src, src_length) {
            panic!("Security violation: source buffer must be in untrusted memory");
        }
    }

    let src = unsafe { from_raw_parts(src, src_length) };
    serde_cbor::from_slice(src).expect("Malformed enclave request")
}

/// Serialize value in trusted memory to response buffer in untrusted memory.
///
/// # EDL
///
/// In order for this function to work, the destination buffer must be declared
/// using the `[user_check]` attribute in the EDL.
///
/// # Panics
///
/// This function will panic if the destination buffer is null, too small to hold
/// the content of the source buffer or if the destination buffer is not in
/// untrusted memory as this may compromise enclave security.
pub fn write_enclave_response<S>(src: &S, dst: *mut u8, dst_capacity: usize, dst_length: *mut usize)
where
    S: Serialize,
{
    if dst.is_null() {
        panic!("Destination buffer must not be null");
    }

    // Ensure that response data is in untrusted memory. This is required because
    // we are using user_check in the EDL so we must do all checks manually. If
    // the pointer was inside the enclave, we could overwrite arbitrary parts of
    // enclave memory.
    #[cfg(target_env = "sgx")]
    {
        if !rsgx_raw_is_outside_enclave(dst, dst_capacity) {
            panic!("Security violation: destination buffer must be in untrusted memory");
        }
    }

    let dst = unsafe { from_raw_parts_mut(dst, dst_capacity) };
    let mut cursor = Cursor::new(dst);
    serde_cbor::to_writer(&mut cursor, src).expect("Failed to encode enclave response");

    unsafe {
        *dst_length = cursor.position() as usize;
    }
}
