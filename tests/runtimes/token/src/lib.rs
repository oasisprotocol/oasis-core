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
use ekiden_storage_base::backend::{InsertOptions, StorageBackend};
#[cfg(target_env = "sgx")]
use ekiden_trusted::db::untrusted::UntrustedStorageBackend;
use ekiden_trusted::enclave::enclave_init;
use ekiden_trusted::runtime::dispatcher::{BatchHandler, RuntimeCallContext};
use ekiden_trusted::runtime::{configure_runtime_dispatch_batch_handler, create_runtime};

enclave_init!();

// Create enclave runtime interface.
with_api! {
    create_runtime!(api);
}

struct MyCustomContext {
    bar: u8,
}

struct TokenBatchHandler;
impl BatchHandler for TokenBatchHandler {
    fn start_batch(&self, ctx: &mut RuntimeCallContext) {
        ctx.runtime = Box::new(MyCustomContext { bar: 42 });
    }

    fn end_batch(&self, ctx: RuntimeCallContext) {
        let my_ctx = *ctx.runtime.downcast::<MyCustomContext>().unwrap();
        assert_eq!(my_ctx.bar, 42);
    }
}

configure_runtime_dispatch_batch_handler!(TokenBatchHandler);

pub fn null(_request: &bool, _ctx: &RuntimeCallContext) -> Result<()> {
    Ok(())
}

#[cfg(target_env = "sgx")]
pub fn null_storage_insert(request: &u64, _ctx: &RuntimeCallContext) -> Result<()> {
    let backend = UntrustedStorageBackend::new();

    for _ in 0..*request {
        backend
            .insert(b"foo".to_vec(), 10, InsertOptions::default())
            .wait()
            .unwrap();
    }

    Ok(())
}

#[cfg(not(target_env = "sgx"))]
pub fn null_storage_insert(_request: &u64, _ctx: &RuntimeCallContext) -> Result<()> {
    panic!("only supported on sgx");
}

#[cfg(target_env = "sgx")]
pub fn list_storage_insert(request: &Vec<Vec<u8>>, _ctx: &RuntimeCallContext) -> Result<()> {
    let backend = UntrustedStorageBackend::new();

    for item in request.iter() {
        backend
            .insert(item.clone(), 10, InsertOptions::default())
            .wait()
            .unwrap();
    }

    Ok(())
}

#[cfg(not(target_env = "sgx"))]
pub fn list_storage_insert(_request: &Vec<String>, _ctx: &RuntimeCallContext) -> Result<()> {
    panic!("only supported on sgx");
}

pub fn create(request: &CreateRequest, _ctx: &RuntimeCallContext) -> Result<CreateResponse> {
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

pub fn transfer(request: &TransferRequest, ctx: &RuntimeCallContext) -> Result<TransferResponse> {
    // Check that custom runtime context works.
    let my_ctx = ctx.runtime.downcast_ref::<MyCustomContext>().unwrap();
    assert_eq!(my_ctx.bar, 42);

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
    _ctx: &RuntimeCallContext,
) -> Result<GetBalanceResponse> {
    let token = TokenContract::new();

    // TODO: Get sender from authenticated request.
    let balance = token.get_balance(&request.get_account().to_owned())?;

    let mut response = GetBalanceResponse::new();
    response.set_balance(balance);

    Ok(response)
}
