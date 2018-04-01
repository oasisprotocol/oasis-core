//! Enclave utilities.
use std::io::Cursor;
use std::slice::{from_raw_parts, from_raw_parts_mut};

#[cfg(target_env = "sgx")]
use sgx_trts::trts::rsgx_raw_is_outside_enclave;

use ekiden_common::serializer::{Deserializable, Serializable};

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
pub fn read_enclave_request<R>(src: *const u8, src_length: usize) -> R
where
    R: Deserializable,
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
    let mut cursor = Cursor::new(src);
    R::read_from(&mut cursor).expect("Malformed enclave request")
}

/// Copy serializable in trusted memory to response buffer in untrusted memory.
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
    S: Serializable,
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

    // Serialize message to output buffer.
    let dst = unsafe { from_raw_parts_mut(dst, dst_capacity) };
    let mut cursor = Cursor::new(dst);
    let length = src.write_to(&mut cursor)
        .expect("Failed to write enclave response");

    unsafe {
        *dst_length = length;
    }
}
