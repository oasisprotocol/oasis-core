use std::sync::Arc;

use anyhow::Result;

use oasis_core_keymanager_api_common::*;
use oasis_core_runtime::{
    dispatcher::Initializer,
    enclave_rpc::{
        dispatcher::{Method as RpcMethod, MethodDescriptor as RpcMethodDescriptor},
        Context as RpcContext,
    },
    rak::RAK,
    Protocol, RpcDemux, RpcDispatcher, TxnDispatcher,
};

use crate::{context, kdf::Kdf, methods, policy::Policy};

/// Initialize the Kdf.
fn init_kdf(req: &InitRequest, ctx: &mut RpcContext) -> Result<SignedInitResponse> {
    let policy_checksum = Policy::global().init(ctx, &req.policy)?;
    Kdf::global().init(req, ctx, policy_checksum)
}

/// Initialize a keymanager with trusted policy signers.
pub fn new_keymanager(signers: TrustedPolicySigners) -> Box<dyn Initializer> {
    // Initializer.
    let init = move |protocol: &Arc<Protocol>,
                     _rak: &Arc<RAK>,
                     _rpc_demux: &mut RpcDemux,
                     rpc: &mut RpcDispatcher|
          -> Option<Box<dyn TxnDispatcher>> {
        // Initialize the set of trusted policy signers.
        set_trusted_policy_signers(signers.clone());

        // Register RPC methods exposed via EnclaveRPC to remote clients.
        rpc.add_method(
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_GET_OR_CREATE_KEYS.to_string(),
                },
                methods::get_or_create_keys,
            ),
            false,
        );
        rpc.add_method(
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_GET_PUBLIC_KEY.to_string(),
                },
                methods::get_public_key,
            ),
            false,
        );
        rpc.add_method(
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_REPLICATE_MASTER_SECRET.to_string(),
                },
                methods::replicate_master_secret,
            ),
            false,
        );

        // Register local methods, for use by the node key manager component.
        rpc.add_method(
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: LOCAL_METHOD_INIT.to_string(),
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

        None
    };

    Box::new(init)
}
