use ekiden_core::contract::contract_api;

contract_api! {
    pub fn null(bool) -> ();

    pub fn null_storage_insert(u64) -> ();

    pub fn list_storage_insert(Vec<Vec<u8>>) -> ();

    pub fn create(CreateRequest) -> CreateResponse;

    pub fn transfer(TransferRequest) -> TransferResponse;

    pub fn get_balance(GetBalanceRequest) -> GetBalanceResponse;
}
