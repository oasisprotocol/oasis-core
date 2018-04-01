use ekiden_common::profile_block;
use ekiden_enclave_trusted::utils::{read_enclave_request, write_enclave_response};

use super::diffs;
use super::handle::DatabaseHandle;

#[no_mangle]
pub extern "C" fn db_state_diff(
    old: *const u8,
    old_length: usize,
    new: *const u8,
    new_length: usize,
    diff: *mut u8,
    diff_capacity: usize,
    diff_length: *mut usize,
) {
    profile_block!();

    let old = read_enclave_request(old, old_length);
    let new = read_enclave_request(new, new_length);

    // TODO: Error handling.
    let result = match diffs::diff(&old, &new) {
        Ok(result) => result,
        _ => panic!("Error while computing difference"),
    };

    // Copy back response.
    write_enclave_response(&result, diff, diff_capacity, diff_length);
}

#[no_mangle]
pub extern "C" fn db_state_apply(
    old: *const u8,
    old_length: usize,
    diff: *const u8,
    diff_length: usize,
    new: *mut u8,
    new_capacity: usize,
    new_length: *mut usize,
) {
    profile_block!();

    let old = read_enclave_request(old, old_length);
    let diff = read_enclave_request(diff, diff_length);

    // TODO: Error handling.
    let result = match diffs::apply(&old, &diff) {
        Ok(result) => result,
        _ => panic!("Error while applying diff"),
    };

    // Copy back response.
    write_enclave_response(&result, new, new_capacity, new_length);
}

#[no_mangle]
pub extern "C" fn db_state_set(state: *const u8, state_length: usize) {
    profile_block!();

    let state = read_enclave_request(state, state_length);

    // TODO: Propagate errors.
    DatabaseHandle::instance()
        .import(&state)
        .expect("Error importing state");
}

#[no_mangle]
pub extern "C" fn db_state_get(state: *mut u8, state_capacity: usize, state_length: *mut usize) {
    profile_block!();

    // TODO: Propagate errors.
    let result = DatabaseHandle::instance()
        .export()
        .expect("Error exporting state");

    // Copy back response.
    write_enclave_response(&result, state, state_capacity, state_length);
}
