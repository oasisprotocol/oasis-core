extern crate failure;
extern crate lazy_static;
extern crate oasis_core_keymanager_api;
extern crate oasis_core_keymanager_lib;
extern crate oasis_core_runtime;

use std::sync::Arc;

mod methods;

use failure::Fallible;

use oasis_core_keymanager_api::*;
use oasis_core_runtime::{
    common::version::Version,
    rak::RAK,
    register_runtime_rpc_methods,
    rpc::{
        dispatcher::{Method as RpcMethod, MethodDescriptor as RpcMethodDescriptor},
        Context as RpcContext,
    },
    version_from_cargo, Protocol, RpcDemux, RpcDispatcher, TxnDispatcher,
};

use oasis_core_keymanager_lib::{context, kdf::Kdf, policy::Policy};

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
        // Initialize the set of trusted policy signers.
        init_trusted_policy_signers();

        // Register RPC methods exposed via EnclaveRPC to remote clients.
        {
            use crate::methods::*;
            with_api! { register_runtime_rpc_methods!(rpc, api); }
        }

        // TODO: Someone that cares can add macros for this, I do not.  Note
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

        let runtime_id = protocol.get_runtime_id();
        let km_proto = protocol.clone(); // Shut up the borrow checker.
        rpc.set_context_initializer(move |ctx: &mut RpcContext| {
            ctx.runtime = Box::new(context::Context {
                runtime_id,
                protocol: km_proto.clone(),
            })
        });
    };

    // Start the runtime.
    oasis_core_runtime::start_runtime(Some(Box::new(init)), version_from_cargo!());
}
