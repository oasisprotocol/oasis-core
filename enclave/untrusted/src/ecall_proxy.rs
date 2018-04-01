use sgx_types::{self, sgx_enclave_id_t, sgx_status_t};

extern "C" {
    pub fn identity_create(
        eid: sgx_enclave_id_t,
        sealed_identity: *mut sgx_types::sgx_sealed_data_t,
        sealed_identity_capacity: usize,
        sealed_identity_length: &mut usize,
    ) -> sgx_status_t;

    pub fn identity_restore(
        eid: sgx_enclave_id_t,
        sealed_identity: *const sgx_types::sgx_sealed_data_t,
        sealed_identity_length: usize,
        public_identity: *mut u8,
        public_identity_capacity: usize,
        public_identity_length: &mut usize,
    ) -> sgx_status_t;

    pub fn identity_create_report(
        eid: sgx_enclave_id_t,
        target_info: &sgx_types::sgx_target_info_t,
        report: &mut sgx_types::sgx_report_t,
    ) -> sgx_status_t;

    pub fn identity_set_av_report(
        eid: sgx_enclave_id_t,
        av_report: *const u8,
        av_report_length: usize,
    ) -> sgx_status_t;
}
