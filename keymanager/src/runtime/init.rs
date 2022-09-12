use anyhow::Result;

use oasis_core_runtime::{
    dispatcher::{Initializer, PostInitState, PreInitState},
    enclave_rpc::{
        dispatcher::{Method as RpcMethod, MethodDescriptor as RpcMethodDescriptor},
        Context as RpcContext,
    },
};

use crate::{
    api::{
        InitRequest, SignedInitResponse, LOCAL_METHOD_INIT, METHOD_GET_OR_CREATE_EPHEMERAL_KEYS,
        METHOD_GET_OR_CREATE_KEYS, METHOD_GET_PUBLIC_EPHEMERAL_KEY, METHOD_GET_PUBLIC_KEY,
        METHOD_REPLICATE_MASTER_SECRET,
    },
    crypto::kdf::Kdf,
    policy::{set_trusted_policy_signers, Policy, TrustedPolicySigners},
};

use super::{context, methods};

/// Initialize the Kdf.
fn init_kdf(req: &InitRequest, ctx: &mut RpcContext) -> Result<SignedInitResponse> {
    let policy_checksum = Policy::global().init(ctx, &req.policy)?;
    Kdf::global().init(req, ctx, policy_checksum)
}

/// Initialize a keymanager with trusted policy signers.
pub fn new_keymanager(signers: TrustedPolicySigners) -> Box<dyn Initializer> {
    // Initializer.
    let init = move |state: PreInitState<'_>| -> PostInitState {
        // Initialize the set of trusted policy signers.
        set_trusted_policy_signers(signers.clone());

        // Register RPC methods exposed via EnclaveRPC to remote clients.
        state.rpc_dispatcher.add_method(
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_GET_OR_CREATE_KEYS.to_string(),
                },
                methods::get_or_create_keys,
            ),
            false,
        );
        state.rpc_dispatcher.add_method(
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_GET_PUBLIC_KEY.to_string(),
                },
                methods::get_public_key,
            ),
            false,
        );
        state.rpc_dispatcher.add_method(
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_GET_OR_CREATE_EPHEMERAL_KEYS.to_string(),
                },
                methods::get_or_create_ephemeral_keys,
            ),
            false,
        );
        state.rpc_dispatcher.add_method(
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_GET_PUBLIC_EPHEMERAL_KEY.to_string(),
                },
                methods::get_public_ephemeral_key,
            ),
            false,
        );
        state.rpc_dispatcher.add_method(
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_REPLICATE_MASTER_SECRET.to_string(),
                },
                methods::replicate_master_secret,
            ),
            false,
        );

        // Register local methods, for use by the node key manager component.
        state.rpc_dispatcher.add_method(
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: LOCAL_METHOD_INIT.to_string(),
                },
                init_kdf,
            ),
            true,
        );

        let runtime_id = state.protocol.get_runtime_id();
        let protocol = state.protocol.clone(); // Shut up the borrow checker.
        state
            .rpc_dispatcher
            .set_context_initializer(move |ctx: &mut RpcContext| {
                ctx.runtime = Box::new(context::Context {
                    runtime_id,
                    protocol: protocol.clone(),
                })
            });

        // No transaction dispatcher.
        PostInitState::default()
    };

    Box::new(init)
}
