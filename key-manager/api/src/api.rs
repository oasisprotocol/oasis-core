use ekiden_core::rpc::rpc_api;

rpc_api! {
    metadata {
        name = key_manager;
        version = "0.1.0";
        client_attestation_required = true;
    }

    rpc get_or_create_keys(GetOrCreateKeyRequest) -> GetOrCreateKeyResponse;

    #[client_attestation(false)]
    rpc get_public_key(GetOrCreateKeyRequest) -> Option<GetOrCreateKeyResponse>;

    #[client_attestation(false)]
    rpc long_term_public_key(GetOrCreateKeyRequest) -> Option<GetOrCreateKeyResponse>;
}
