use sgx_types::*;

extern "C" {
    pub fn db_set_transfer_buffer(
        eid: sgx_enclave_id_t,
        buffer: *mut u8,
        buffer_capacity: usize,
    ) -> sgx_status_t;

    pub fn db_set_root_hash(eid: sgx_enclave_id_t, root_hash: *const u8) -> sgx_status_t;

    pub fn db_commit(eid: sgx_enclave_id_t, root_hash: *mut u8) -> sgx_status_t;
}
