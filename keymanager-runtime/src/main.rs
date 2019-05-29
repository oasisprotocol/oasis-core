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
mod methods;

use failure::Fallible;

use ekiden_keymanager_api::*;
use ekiden_runtime::{
    register_runtime_rpc_methods,
    rpc::{
        dispatcher::{Method as RpcMethod, MethodDescriptor as RpcMethodDescriptor},
        Context as RpcContext,
    },
    RpcDemux, RpcDispatcher, TxnDispatcher,
};

use self::kdf::Kdf;

/// Initialize the Kdf.
fn init_kdf(_req: &InitRequest, ctx: &mut RpcContext) -> Fallible<SignedInitResponse> {
    // TODO: Based on the InitRequest, and persisted state (if any):
    //  * Load the persisted state.
    //  * Generate a new master secret.
    //  * Replicate the master secret.

    Kdf::global().init(&ctx)
}

fn main() {
    // Initializer.
    let init = |_: &_,
                _: &_,
                _rpc_demux: &mut RpcDemux,
                rpc: &mut RpcDispatcher,
                _txn: &mut TxnDispatcher| {
        // Register RPC methods exposed via EnclaveRPC to remote clients.
        {
            use crate::methods::*;
            with_api! { register_runtime_rpc_methods!(rpc, api); }
        }

        // TODO: Somone that cares can add macros for this, I do not.  Note
        // that these are local methods, for use by the node key manager
        // component.
        rpc.add_method(
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: "init".to_string(),
                },
                init_kdf,
            ),
            true,
        );
    };

    // Start the runtime.
    ekiden_runtime::start_runtime(Some(Box::new(init)));
}
