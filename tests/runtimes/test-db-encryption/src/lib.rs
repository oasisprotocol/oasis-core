extern crate protobuf;

extern crate ekiden_core;
extern crate ekiden_trusted;

extern crate test_db_encryption_api;

#[macro_use]
extern crate lazy_static;

use std::str::FromStr;
#[cfg(not(target_env = "sgx"))]
use std::sync::Mutex;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutex as Mutex;

use test_db_encryption_api::{with_api, FetchEncryptedRequest, FetchEncryptedResponse,
                             SetKMEnclaveRequest, SetKMEnclaveResponse, StoreEncryptedRequest,
                             StoreEncryptedResponse};

use ekiden_core::bytes::H256;
use ekiden_core::enclave::quote::MrEnclave;
use ekiden_core::error::Result;
use ekiden_trusted::db::{DBKeyManagerConfig, Database, DatabaseHandle};
use ekiden_trusted::enclave::enclave_init;
use ekiden_trusted::runtime::create_runtime;
use ekiden_trusted::runtime::dispatcher::RuntimeCallContext;

enclave_init!();

// Create enclave contract interface.
with_api! {
    create_runtime!(api);
}

lazy_static! {
    // Key manager's enclave.
    static ref KM_ENCLAVE: Mutex<MrEnclave> = Mutex::new(MrEnclave::zero());
}

pub fn set_km_enclave(
    request: &SetKMEnclaveRequest,
    _ctx: &RuntimeCallContext,
) -> Result<SetKMEnclaveResponse> {
    *KM_ENCLAVE.lock().unwrap() = MrEnclave::from_str(request.get_mrenclave())?;

    Ok(SetKMEnclaveResponse::new())
}

#[cfg(target_env = "sgx")]
pub fn store_encrypted(
    request: &StoreEncryptedRequest,
    _ctx: &RuntimeCallContext,
) -> Result<StoreEncryptedResponse> {
    let key = request.get_key().as_bytes();
    let value = request.get_value().as_bytes();

    let mut db = DatabaseHandle::instance();

    // Configure the key manager enclave.
    db.configure_key_manager(DBKeyManagerConfig {
        mrenclave: KM_ENCLAVE.lock().unwrap().clone(),
    });

    // Use the test contract for now.
    let contract_id = H256::from_str(&"0".repeat(64))?;

    // Store with encryption!
    db.with_encryption(contract_id, |db| {
        db.insert(key, value);
    });

    let mut response = StoreEncryptedResponse::new();
    response.set_ok(true);
    Ok(response)
}

#[cfg(not(target_env = "sgx"))]
pub fn store_encrypted(
    request: &StoreEncryptedRequest,
    _ctx: &RuntimeCallContext,
) -> Result<StoreEncryptedResponse> {
    panic!("The DB encryption test enclave only works in SGX mode!");
}

#[cfg(target_env = "sgx")]
pub fn fetch_encrypted(
    request: &FetchEncryptedRequest,
    _ctx: &RuntimeCallContext,
) -> Result<FetchEncryptedResponse> {
    let key = request.get_key().as_bytes();

    let mut db = DatabaseHandle::instance();

    // Configure the key manager enclave.
    db.configure_key_manager(DBKeyManagerConfig {
        mrenclave: KM_ENCLAVE.lock().unwrap().clone(),
    });

    // Use the test contract for now.
    let contract_id = H256::from_str(&"0".repeat(64))?;

    let mut response = FetchEncryptedResponse::new();

    // Fetch with encryption!
    db.with_encryption(contract_id, |db| match db.get(key) {
        None => {
            response.set_ok(false);
            response.set_value(String::from(""));
        }
        Some(v) => {
            response.set_ok(true);
            response.set_value(String::from_utf8(v).unwrap());
        }
    });

    Ok(response)
}

#[cfg(not(target_env = "sgx"))]
pub fn fetch_encrypted(
    request: &FetchEncryptedRequest,
    _ctx: &RuntimeCallContext,
) -> Result<FetchEncryptedResponse> {
    panic!("The DB encryption test enclave only works in SGX mode!");
}
