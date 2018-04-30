//! RPCs provided by the contract interface.
use std::ops::Deref;

use ekiden_common::bytes::H256;
use ekiden_common::error::Result;
use ekiden_contract_common::call::{Generic, SignedContractCall};
use ekiden_contract_common::protocol;
use ekiden_rpc_common::reflection::ApiMethodDescriptor;
use ekiden_rpc_trusted::dispatcher::{Dispatcher, EnclaveMethod};
use ekiden_rpc_trusted::request::Request;

use super::batch::Batcher;

#[cfg(target_env = "sgx")]
global_ctors_object! {
    ENCLAVE_CONTRACT_RPC_INIT, enclave_contract_rpc_init = {
        register_contract_rpcs();
    }
}

/// Register RPCs provided by the contract interface.
pub fn register_contract_rpcs() {
    let mut dispatcher = Dispatcher::get();

    // Submit an async contract request.
    dispatcher.add_method(EnclaveMethod::new(
        ApiMethodDescriptor {
            name: protocol::METHOD_CONTRACT_SUBMIT.to_owned(),
            client_attestation_required: false,
        },
        contract_submit,
    ));

    // Reveal output decryption key.
    // TODO.
}

/// Submit an async contract request.
fn contract_submit(request: &Request<SignedContractCall<Generic>>) -> Result<H256> {
    // Add the given signed request to the current batch.
    let mut batcher = Batcher::get();
    Ok(batcher.add(request.deref().clone()))
}
