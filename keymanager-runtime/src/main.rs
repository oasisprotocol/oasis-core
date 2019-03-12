extern crate byteorder;
extern crate ekiden_keymanager_api;
extern crate ekiden_runtime;
extern crate failure;
extern crate lazy_static;
extern crate serde_cbor;

mod key_store;

use failure::Fallible;

use ekiden_keymanager_api::*;
use ekiden_runtime::{
    register_runtime_rpc_methods, rpc::Context as RpcContext, RpcDispatcher, TxnDispatcher,
};

use self::key_store::KeyStore;

// We have not implemented key-expiry yet. So give all keys the maximum expiry of 2^53-1
// because (as a convenience) that is the maximum safe number to use in JavaScript and its
// more than enough to account for enough time.
static MAX_KEY_TIMESTAMP: u64 = (1 << 53) - 1;

/// See `KeyStore::get_or_create_keys`.
fn get_or_create_keys(contract_id: &ContractId, ctx: &mut RpcContext) -> Fallible<ContractKey> {
    // Authenticate session info (this requires all clients are SGX enclaves).
    #[cfg_attr(not(target_env = "sgx"), allow(unused))]
    let si = ctx.session_info.as_ref();

    #[cfg(target_env = "sgx")]
    let _si = si.ok_or(KeyManagerError::NotAuthenticated)?;

    // TODO: Namespace all keys based on si.authenticated_avr.mr_enclave so that the keys
    //       are never released to an incorrect enclave.

    KeyStore::global().get_or_create_keys(contract_id)
}

/// See `KeyStore::get_public_key`.
fn get_public_key(
    contract_id: &ContractId,
    _ctx: &mut RpcContext,
) -> Fallible<Option<SignedPublicKey>> {
    let ks = KeyStore::global();
    let pk = ks.get_public_key(contract_id)?;
    pk.map_or(Ok(None), |pk| {
        Ok(Some(ks.sign_public_key(pk, Some(MAX_KEY_TIMESTAMP))?))
    })
}

/// See `KeyStore::get_public_key`.
fn get_long_term_public_key(
    contract_id: &ContractId,
    _ctx: &mut RpcContext,
) -> Fallible<Option<SignedPublicKey>> {
    let ks = KeyStore::global();
    let pk = ks.get_public_key(contract_id)?;
    pk.map_or(Ok(None), |pk| Ok(Some(ks.sign_public_key(pk, None)?)))
}

fn main() {
    // Initializer.
    let init = |_: &_, _: &_, rpc: &mut RpcDispatcher, _txn: &mut TxnDispatcher| {
        with_api! { register_runtime_rpc_methods!(rpc, api); }
    };

    // Start the runtime.
    ekiden_runtime::start_runtime(Some(Box::new(init)));
}
