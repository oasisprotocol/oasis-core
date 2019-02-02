use std::slice::from_raw_parts;

use ekiden_common::{bytes::H256, futures::Future};
use ekiden_storage_base::InsertOptions;

use super::enclave::{current_storage, with_transfer_buffer};

#[no_mangle]
pub extern "C" fn untrusted_db_get(key: *const u8, value_length: *mut usize, result: *mut u8) {
    measure_histogram_timer!("untrusted_db_get");

    let storage = current_storage();

    let key = H256::from(unsafe { from_raw_parts(key, H256::len()) });
    // Since this is invoked from an OCALL running in a separate thread and we are currently
    // using synchronous OCALLs, we can wait on the future here.
    match storage.get(key).wait() {
        Ok(value) => {
            // Copy value to transfer buffer.
            with_transfer_buffer(|buffer| buffer[..value.len()].clone_from_slice(&value));

            unsafe {
                *value_length = value.len();
                *result = 0;
            }
        }
        Err(_error) => {
            // TODO: Should we transfer the error message?
            unsafe {
                *result = 1;
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn untrusted_db_insert(value_length: usize, expiry: u64, result: *mut u8) {
    measure_histogram_timer!("untrusted_db_insert");

    let storage = current_storage();

    // Copy value from transfer buffer.
    let value = with_transfer_buffer(|buffer| buffer[..value_length].to_owned());

    measure_configure!(
        "insert_size",
        "Size of values inserted into storage for contract DB.",
        MetricConfig::Histogram {
            buckets: vec![0., 1., 4., 16., 64., 256., 1024., 4096., 16384.],
        }
    );
    measure_histogram!("insert_size", value.len());
    match storage
        .insert(value, expiry, InsertOptions::default())
        .wait()
    {
        Ok(()) => unsafe {
            *result = 0;
        },
        Err(error) => {
            // TODO: Should we transfer the error message?
            error!(
                "Failed to insert data to storage backend: {}",
                error.message
            );
            unsafe {
                *result = 1;
            }
        }
    }
}
