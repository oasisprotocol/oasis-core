use std::sync::Arc;

use oasis_core_runtime::{
    dispatcher::{Initializer, PostInitState, PreInitState},
    enclave_rpc::dispatcher::Handler,
    protocol::ProtocolUntrustedLocalStorage,
};

use crate::{
    churp::Churp,
    policy::{set_trusted_policy_signers, TrustedPolicySigners},
};

use super::secrets::Secrets;

/// Initialize a keymanager with trusted policy signers.
pub fn new_keymanager(signers: TrustedPolicySigners) -> Box<dyn Initializer> {
    // Initializer.
    let init = move |state: PreInitState<'_>| -> PostInitState {
        // Initialize the set of trusted policy signers.
        set_trusted_policy_signers(signers.clone());

        let secrets = Box::leak(Box::new(Secrets::new(
            state.identity.clone(),
            state.consensus_verifier.clone(),
            state.protocol.clone(),
        )));

        let churp = Box::leak(Box::new(Churp::new(
            state.protocol.get_runtime_id(),
            state.identity.clone(),
            state.consensus_verifier.clone(),
            Arc::new(ProtocolUntrustedLocalStorage::new(state.protocol.clone())),
        )));

        state.rpc_dispatcher.add_methods(secrets.methods());
        state.rpc_dispatcher.add_methods(churp.methods());

        // No transaction dispatcher.
        PostInitState::default()
    };

    Box::new(init)
}
