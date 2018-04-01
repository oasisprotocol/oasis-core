use ekiden_core::rpc::rpc_api;

rpc_api! {
    metadata {
        name = token;
        version = "0.1.0";
        client_attestation_required = false;
    }

    rpc create(CreateRequest) -> CreateResponse;

    rpc transfer(TransferRequest) -> TransferResponse;

    rpc get_balance(GetBalanceRequest) -> GetBalanceResponse;
}
