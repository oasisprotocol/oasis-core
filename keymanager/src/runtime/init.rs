use oasis_core_runtime::{
    dispatcher::{Initializer, PostInitState, PreInitState},
    enclave_rpc::{
        dispatcher::{Method as RpcMethod, MethodDescriptor as RpcMethodDescriptor},
        types::Kind as RpcKind,
        Context as RpcContext,
    },
};

use crate::{
    api::{
        LOCAL_METHOD_GENERATE_EPHEMERAL_SECRET, LOCAL_METHOD_GENERATE_MASTER_SECRET,
        LOCAL_METHOD_INIT, LOCAL_METHOD_LOAD_EPHEMERAL_SECRET, LOCAL_METHOD_LOAD_MASTER_SECRET,
        METHOD_GET_OR_CREATE_EPHEMERAL_KEYS, METHOD_GET_OR_CREATE_KEYS,
        METHOD_GET_PUBLIC_EPHEMERAL_KEY, METHOD_GET_PUBLIC_KEY, METHOD_REPLICATE_EPHEMERAL_SECRET,
        METHOD_REPLICATE_MASTER_SECRET,
    },
    policy::{set_trusted_policy_signers, TrustedPolicySigners},
};

use super::{context, methods};

/// Initialize a keymanager with trusted policy signers.
pub fn new_keymanager(signers: TrustedPolicySigners) -> Box<dyn Initializer> {
    // Initializer.
    let init = move |state: PreInitState<'_>| -> PostInitState {
        // Initialize the set of trusted policy signers.
        set_trusted_policy_signers(signers.clone());

        // Register RPC methods exposed via EnclaveRPC to remote clients.
        state.rpc_dispatcher.add_method(RpcMethod::new(
            RpcMethodDescriptor {
                name: METHOD_GET_OR_CREATE_KEYS.to_string(),
                kind: RpcKind::NoiseSession,
            },
            methods::get_or_create_keys,
        ));
        state.rpc_dispatcher.add_method(RpcMethod::new(
            RpcMethodDescriptor {
                name: METHOD_GET_PUBLIC_KEY.to_string(),
                kind: RpcKind::InsecureQuery,
            },
            methods::get_public_key,
        ));
        state.rpc_dispatcher.add_method(RpcMethod::new(
            RpcMethodDescriptor {
                name: METHOD_GET_OR_CREATE_EPHEMERAL_KEYS.to_string(),
                kind: RpcKind::NoiseSession,
            },
            methods::get_or_create_ephemeral_keys,
        ));
        state.rpc_dispatcher.add_method(RpcMethod::new(
            RpcMethodDescriptor {
                name: METHOD_GET_PUBLIC_EPHEMERAL_KEY.to_string(),
                kind: RpcKind::InsecureQuery,
            },
            methods::get_public_ephemeral_key,
        ));
        state.rpc_dispatcher.add_method(RpcMethod::new(
            RpcMethodDescriptor {
                name: METHOD_REPLICATE_MASTER_SECRET.to_string(),
                kind: RpcKind::NoiseSession,
            },
            methods::replicate_master_secret,
        ));
        state.rpc_dispatcher.add_method(RpcMethod::new(
            RpcMethodDescriptor {
                name: METHOD_REPLICATE_EPHEMERAL_SECRET.to_string(),
                kind: RpcKind::NoiseSession,
            },
            methods::replicate_ephemeral_secret,
        ));

        // Register local methods, for use by the node key manager component.
        state.rpc_dispatcher.add_method(RpcMethod::new(
            RpcMethodDescriptor {
                name: LOCAL_METHOD_INIT.to_string(),
                kind: RpcKind::LocalQuery,
            },
            methods::init_kdf,
        ));
        state.rpc_dispatcher.add_method(RpcMethod::new(
            RpcMethodDescriptor {
                name: LOCAL_METHOD_GENERATE_MASTER_SECRET.to_string(),
                kind: RpcKind::LocalQuery,
            },
            methods::generate_master_secret,
        ));
        state.rpc_dispatcher.add_method(RpcMethod::new(
            RpcMethodDescriptor {
                name: LOCAL_METHOD_GENERATE_EPHEMERAL_SECRET.to_string(),
                kind: RpcKind::LocalQuery,
            },
            methods::generate_ephemeral_secret,
        ));
        state.rpc_dispatcher.add_method(RpcMethod::new(
            RpcMethodDescriptor {
                name: LOCAL_METHOD_LOAD_MASTER_SECRET.to_string(),
                kind: RpcKind::LocalQuery,
            },
            methods::load_master_secret,
        ));
        state.rpc_dispatcher.add_method(RpcMethod::new(
            RpcMethodDescriptor {
                name: LOCAL_METHOD_LOAD_EPHEMERAL_SECRET.to_string(),
                kind: RpcKind::LocalQuery,
            },
            methods::load_ephemeral_secret,
        ));

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
