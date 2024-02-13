use oasis_core_runtime::{
    dispatcher::{Initializer, PostInitState, PreInitState},
    enclave_rpc::dispatcher::Handler,
};

use crate::policy::{set_trusted_policy_signers, TrustedPolicySigners};

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

        state.rpc_dispatcher.add_methods(secrets.methods());

        // No transaction dispatcher.
        PostInitState::default()
    };

    Box::new(init)
}
