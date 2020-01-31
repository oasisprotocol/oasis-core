//! Methods exported to remote clients via EnclaveRPC.
use failure::Fallible;
use oasis_core_keymanager_api::*;
use oasis_core_runtime::rpc::Context as RpcContext;

use oasis_core_keymanager_lib::{kdf::Kdf, policy::Policy};

/// See `Kdf::get_or_create_keys`.
pub fn get_or_create_keys(req: &RequestIds, ctx: &mut RpcContext) -> Fallible<ContractKey> {
    // Authenticate the source enclave based on the MRSIGNER/MRENCLAVE/request
    // so that the keys are never released to an incorrect enclave.
    if !Policy::unsafe_skip() {
        let si = ctx.session_info.as_ref();
        let si = si.ok_or(KeyManagerError::NotAuthenticated)?;
        let their_id = &si.authenticated_avr.identity;

        Policy::global().may_get_or_create_keys(their_id, &req)?;
    }

    Kdf::global().get_or_create_keys(req)
}

/// See `Kdf::get_public_key`.
pub fn get_public_key(
    req: &RequestIds,
    _ctx: &mut RpcContext,
) -> Fallible<Option<SignedPublicKey>> {
    let kdf = Kdf::global();

    // No authentication, absolutely anyone is allowed to query public keys.

    let pk = kdf.get_public_key(req)?;
    pk.map_or(Ok(None), |pk| Ok(Some(kdf.sign_public_key(pk)?)))
}

/// See `Kdf::replicate_master_secret`.
pub fn replicate_master_secret(
    _req: &ReplicateRequest,
    ctx: &mut RpcContext,
) -> Fallible<ReplicateResponse> {
    // Authenticate the source enclave based on the MRSIGNER/MRNELCAVE.
    if !Policy::unsafe_skip() {
        let si = ctx.session_info.as_ref();
        let si = si.ok_or(KeyManagerError::NotAuthenticated)?;
        let their_id = &si.authenticated_avr.identity;

        Policy::global().may_replicate_master_secret(their_id)?;
    }

    Kdf::global().replicate_master_secret()
}
