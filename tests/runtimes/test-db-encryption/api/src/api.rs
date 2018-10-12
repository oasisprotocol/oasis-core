use ekiden_core::runtime::runtime_api;

runtime_api! {
    pub fn set_km_enclave(SetKMEnclaveRequest) -> SetKMEnclaveResponse;
    pub fn store_encrypted(StoreEncryptedRequest) -> StoreEncryptedResponse;
    pub fn fetch_encrypted(FetchEncryptedRequest) -> FetchEncryptedResponse;
}
