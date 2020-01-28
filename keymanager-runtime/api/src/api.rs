use oasis_core_runtime::runtime_api;

runtime_api! {
    pub fn get_or_create_keys(RequestIds) -> ContractKey;

    pub fn get_public_key(RequestIds) -> Option<SignedPublicKey>;

    pub fn replicate_master_secret(ReplicateRequest) -> ReplicateResponse;
}
