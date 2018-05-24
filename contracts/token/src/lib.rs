#![feature(use_extern_macros)]

extern crate protobuf;

extern crate ekiden_core;
extern crate ekiden_trusted;

extern crate token_api;

mod token_contract;

use token_api::{with_api, CreateRequest, CreateResponse, GetBalanceRequest, GetBalanceResponse,
                TransferRequest, TransferResponse};
use token_contract::TokenContract;

use ekiden_core::error::Result;
use ekiden_trusted::contract::create_contract;
use ekiden_trusted::enclave::enclave_init;

enclave_init!();

// Create enclave contract interface.
with_api! {
    create_contract!(api);
}

pub fn create(request: &CreateRequest) -> Result<CreateResponse> {
    let token = TokenContract::new();

    // TODO: Get sender from authenticated request.
    token.create(
        request.get_sender().to_owned(),
        request.get_token_name().to_owned(),
        request.get_token_symbol().to_owned(),
        request.get_initial_supply(),
    )?;

    Ok(CreateResponse::new())
}

pub fn transfer(request: &TransferRequest) -> Result<TransferResponse> {
    let token = TokenContract::new();

    // TODO: Get sender from authenticated request.
    token.transfer(
        request.get_sender().to_owned(),
        request.get_destination().to_owned(),
        request.get_value(),
    )?;

    Ok(TransferResponse::new())
}

pub fn get_balance(request: &GetBalanceRequest) -> Result<GetBalanceResponse> {
    let token = TokenContract::new();

    // TODO: Get sender from authenticated request.
    let balance = token.get_balance(&request.get_account().to_owned())?;

    let mut response = GetBalanceResponse::new();
    response.set_balance(balance);

    Ok(response)
}
