use ekiden_core::contract::contract_api;

contract_api! {
    pub fn create(CreateRequest) -> CreateResponse;

    pub fn transfer(TransferRequest) -> TransferResponse;

    pub fn get_balance(GetBalanceRequest) -> GetBalanceResponse;
}
