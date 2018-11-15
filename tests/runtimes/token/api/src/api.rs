use ekiden_core::runtime::runtime_api;

runtime_api! {
    pub fn null(Unique<bool>) -> ();

    pub fn null_storage_insert(Unique<u64>) -> ();

    pub fn list_storage_insert(Unique<Vec<Vec<u8>>>) -> ();

    pub fn create(Unique<CreateRequest>) -> CreateResponse;

    pub fn transfer(Unique<TransferRequest>) -> TransferResponse;

    pub fn get_balance(Unique<GetBalanceRequest>) -> GetBalanceResponse;
}
