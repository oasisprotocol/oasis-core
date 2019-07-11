extern crate ekiden_keymanager_api;
extern crate ekiden_keymanager_client;
extern crate ekiden_runtime;
extern crate failure;
extern crate io_context;
extern crate lazy_static;
extern crate lru;
extern crate rand;
extern crate sp800_185;
extern crate tiny_keccak;
extern crate x25519_dalek;
extern crate zeroize;

use std::{str::FromStr, sync::Arc};

mod context;
mod kdf;
mod methods;
mod policy;

use failure::Fallible;

use ekiden_keymanager_api::*;
use ekiden_runtime::{
    common::runtime::RuntimeId,
    rak::RAK,
    register_runtime_rpc_methods,
    rpc::{
        dispatcher::{Method as RpcMethod, MethodDescriptor as RpcMethodDescriptor},
        Context as RpcContext,
    },
    Protocol, RpcDemux, RpcDispatcher, TxnDispatcher,
};

use self::{kdf::Kdf, policy::Policy};

/// Initialize the Kdf.
fn init_kdf(req: &InitRequest, ctx: &mut RpcContext) -> Fallible<SignedInitResponse> {
    let policy_checksum = Policy::global().init(ctx, &req.policy)?;
    Kdf::global().init(&req, ctx, policy_checksum)
}

fn main() {
    // Initializer.
    let init = |protocol: &Arc<Protocol>,
                _rak: &Arc<RAK>,
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

        // HACK: There is no nice way of passing in the runtime ID at compile
        // time yet.
        let runtime_id =
            RuntimeId::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();

        let km_proto = protocol.clone(); // Shut up the borrow checker.
        rpc.set_context_initializer(move |ctx: &mut RpcContext| {
            ctx.runtime = Box::new(context::Context {
                runtime_id,
                protocol: km_proto.clone(),
            })
        });
    };

    // Start the runtime.
    ekiden_runtime::start_runtime(Some(Box::new(init)));
}
