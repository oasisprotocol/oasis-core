use sgx_types::*;

extern "C" {
    pub fn db_state_diff(
        eid: sgx_enclave_id_t,
        old: *const u8,
        old_length: usize,
        new: *const u8,
        new_length: usize,
        diff: *mut u8,
        diff_capacity: usize,
        diff_length: *mut usize,
    ) -> sgx_status_t;

    pub fn db_state_apply(
        eid: sgx_enclave_id_t,
        old: *const u8,
        old_length: usize,
        diff: *const u8,
        diff_length: usize,
        new: *mut u8,
        new_capacity: usize,
        new_length: *mut usize,
    ) -> sgx_status_t;

    pub fn db_state_set(
        eid: sgx_enclave_id_t,
        state: *const u8,
        state_length: usize,
    ) -> sgx_status_t;

    pub fn db_state_get(
        eid: sgx_enclave_id_t,
        state: *mut u8,
        state_capacity: usize,
        state_length: *mut usize,
    ) -> sgx_status_t;
}
