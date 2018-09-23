extern crate protobuf;

extern crate ekiden_core;
extern crate ekiden_storage_base;
extern crate ekiden_trusted;

extern crate token_api;

mod token_contract;

use token_api::{with_api, CreateRequest, CreateResponse, GetBalanceRequest, GetBalanceResponse,
                TransferRequest, TransferResponse};
use token_contract::TokenContract;

use ekiden_core::error::Result;
use ekiden_core::futures::prelude::*;
#[cfg(target_env = "sgx")]
use ekiden_storage_base::backend::StorageBackend;
use ekiden_trusted::contract::create_contract;
use ekiden_trusted::contract::dispatcher::ContractCallContext;
#[cfg(target_env = "sgx")]
use ekiden_trusted::db::untrusted::UntrustedStorageBackend;
use ekiden_trusted::enclave::enclave_init;

enclave_init!();

// Create enclave contract interface.
with_api! {
    create_contract!(api);
}

pub fn null(_request: &bool, _ctx: &ContractCallContext) -> Result<()> {
    Ok(())
}

#[cfg(target_env = "sgx")]
pub fn null_storage_insert(request: &u64, _ctx: &ContractCallContext) -> Result<()> {
    let backend = UntrustedStorageBackend::new();

    for _ in 0..*request {
        backend.insert(b"foo".to_vec(), 10).wait().unwrap();
    }

    Ok(())
}

#[cfg(not(target_env = "sgx"))]
pub fn null_storage_insert(_request: &u64, _ctx: &ContractCallContext) -> Result<()> {
    panic!("only supported on sgx");
}

#[cfg(target_env = "sgx")]
pub fn list_storage_insert(request: &Vec<Vec<u8>>, _ctx: &ContractCallContext) -> Result<()> {
    let backend = UntrustedStorageBackend::new();

    for item in request.iter() {
        backend.insert(item.clone(), 10).wait().unwrap();
    }

    Ok(())
}

#[cfg(not(target_env = "sgx"))]
pub fn list_storage_insert(_request: &Vec<String>, _ctx: &ContractCallContext) -> Result<()> {
    panic!("only supported on sgx");
}

pub fn create(request: &CreateRequest, _ctx: &ContractCallContext) -> Result<CreateResponse> {
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

pub fn transfer(request: &TransferRequest, _ctx: &ContractCallContext) -> Result<TransferResponse> {
    let token = TokenContract::new();

    // TODO: Get sender from authenticated request.
    token.transfer(
        request.get_sender().to_owned(),
        request.get_destination().to_owned(),
        request.get_value(),
    )?;

    Ok(TransferResponse::new())
}

pub fn get_balance(
    request: &GetBalanceRequest,
    _ctx: &ContractCallContext,
) -> Result<GetBalanceResponse> {
    let token = TokenContract::new();

    // TODO: Get sender from authenticated request.
    let balance = token.get_balance(&request.get_account().to_owned())?;

    let mut response = GetBalanceResponse::new();
    response.set_balance(balance);

    Ok(response)
}
