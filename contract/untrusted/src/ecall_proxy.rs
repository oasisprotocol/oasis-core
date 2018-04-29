use sgx_types::*;

extern "C" {
    /// Check if the enclave has a batch ready for execution and copy it over.
    pub fn contract_take_batch(
        eid: sgx_enclave_id_t,
        call_batch_data: *const u8,
        call_batch_capacity: usize,
        call_batch_length: *mut usize,
    ) -> sgx_status_t;

    /// Process batch of contract calls.
    pub fn contract_call_batch(
        eid: sgx_enclave_id_t,
        call_batch_data: *const u8,
        call_batch_length: usize,
        output_batch_data: *const u8,
        output_batch_capacity: usize,
        output_batch_length: *mut usize,
    ) -> sgx_status_t;
}
