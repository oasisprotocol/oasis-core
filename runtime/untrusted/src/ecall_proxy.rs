use sgx_types::*;

extern "C" {
    /// Process batch of runtime calls.
    pub fn runtime_call_batch(
        eid: sgx_enclave_id_t,
        call_batch_data: *const u8,
        call_batch_length: usize,
        block_header_data: *const u8,
        block_header_length: usize,
        output_batch_data: *const u8,
        output_batch_capacity: usize,
        output_batch_length: *mut usize,
    ) -> sgx_status_t;
}
