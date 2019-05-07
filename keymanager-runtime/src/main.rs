extern crate byteorder;
extern crate ekiden_keymanager_api;
extern crate ekiden_runtime;
extern crate failure;
extern crate io_context;
extern crate lazy_static;
extern crate lru;
extern crate rand;
extern crate serde_cbor;
extern crate sp800_185;
extern crate x25519_dalek;
extern crate zeroize;

mod kdf;

use failure::Fallible;

use ekiden_keymanager_api::*;
use ekiden_runtime::{
    register_runtime_rpc_methods, rpc::Context as RpcContext, RpcDispatcher, TxnDispatcher,
};

use self::kdf::Kdf;

// We have not implemented key-expiry yet. So give all keys the maximum expiry of 2^53-1
// because (as a convenience) that is the maximum safe number to use in JavaScript and its
// more than enough to account for enough time.
static MAX_KEY_TIMESTAMP: u64 = (1 << 53) - 1;

/// Initialize the Kdf.
fn init(ctx: &mut RpcContext) -> Fallible<()> {
    Kdf::global().init(&ctx)
}

/// See `Kdf::get_or_create_keys`.
fn get_or_create_keys(req: &RequestIds, ctx: &mut RpcContext) -> Fallible<ContractKey> {
    init(ctx)?; // HACK HACK HACK

    // Authenticate session info (this requires all clients are SGX enclaves).
    #[cfg_attr(not(target_env = "sgx"), allow(unused))]
    let si = ctx.session_info.as_ref();

    #[cfg(target_env = "sgx")]
    let _si = si.ok_or(KeyManagerError::NotAuthenticated)?;

    // TODO: Namespace all keys based on the tuple (req.runtime_id,
    // req.contract_id, si.authenticated_avr.mr_enclave) so that the keys
    // are never released to an incorrect enclave.

    Kdf::global().get_or_create_keys(req)
}

/// See `Kdf::get_public_key`.
fn get_public_key(req: &RequestIds, ctx: &mut RpcContext) -> Fallible<Option<SignedPublicKey>> {
    init(ctx)?; // HACK HACK HACK

    let kdf = Kdf::global();
    let pk = kdf.get_public_key(req)?;
    pk.map_or(Ok(None), |pk| {
        Ok(Some(kdf.sign_public_key(pk, Some(MAX_KEY_TIMESTAMP))?))
    })
}

/// See `Kdf::get_public_key`.
fn get_long_term_public_key(
    req: &RequestIds,
    ctx: &mut RpcContext,
) -> Fallible<Option<SignedPublicKey>> {
    init(ctx)?; // HACK HACK HACK

    let kdf = Kdf::global();
    let pk = kdf.get_public_key(req)?;
    pk.map_or(Ok(None), |pk| Ok(Some(kdf.sign_public_key(pk, None)?)))
}

fn main() {
    // Initializer.
    let init = |_: &_, _: &_, rpc: &mut RpcDispatcher, _txn: &mut TxnDispatcher| {
        with_api! { register_runtime_rpc_methods!(rpc, api); }
    };

    // Start the runtime.
    ekiden_runtime::start_runtime(Some(Box::new(init)));
}
