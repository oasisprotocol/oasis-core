use sgx_types::*;

extern "C" {
    /// Call enclave RPC system.
    pub fn rpc_call(
        eid: sgx_enclave_id_t,
        request_data: *const u8,
        request_length: usize,
        response_data: *const u8,
        response_capacity: usize,
        response_length: *mut usize,
    ) -> sgx_status_t;
}
