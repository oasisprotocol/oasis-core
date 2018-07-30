#![feature(use_extern_macros)]

#[macro_use]
extern crate lazy_static;
extern crate protobuf;
extern crate serde_cbor;
extern crate sodalite;

extern crate ekiden_core;
extern crate ekiden_keymanager_api;
extern crate ekiden_keymanager_common;
extern crate ekiden_trusted;
#[macro_use]
extern crate ekiden_enclave_logger;

use ekiden_core::error::Result;
use ekiden_core::bytes::H256;
use ekiden_keymanager_api::{with_api, GetOrCreateKeyRequest, GetOrCreateKeyResponse};
use ekiden_trusted::enclave::enclave_init;
use ekiden_trusted::rpc::create_enclave_rpc;
use ekiden_trusted::rpc::request::Request;

mod key_store;
use key_store::KeyStore;

enclave_init!();

// Create enclave RPC handlers.
with_api! {
    create_enclave_rpc!(api);
}

pub fn get_or_create_keys(
    request: &Request<GetOrCreateKeyRequest>,
) -> Result<GetOrCreateKeyResponse> {
    let mut response = GetOrCreateKeyResponse::new();
    // Query the key store.
    {
        let mut key_store = KeyStore::get();
        // TODO: verify MR_ENCLAVE in a meaningful way. See #694.
        let _mr_enclave = request.get_client_mr_enclave();

        let keys =
            key_store.get_or_create_keys(H256::from_slice(request.get_contract_id()))?;
        response.set_key(serde_cbor::to_vec(&keys)?);
    }

    Ok(response)
}

pub fn get_public_key(request: &Request<GetOrCreateKeyRequest>) -> Result<GetOrCreateKeyResponse> {
    let mut response = GetOrCreateKeyResponse::new();
    // Query the key store.
    {
        let key_store = KeyStore::get();
        let keys = key_store.get_public_key(H256::from_slice(request.get_contract_id()))?;
        response.set_key(serde_cbor::to_vec(&keys)?);
    }

    Ok(response)
}
