//! Methods exported to remote clients via EnclaveRPC.
use ekiden_keymanager_api::*;
use ekiden_runtime::rpc::Context as RpcContext;
use failure::Fallible;

#[cfg(target_env = "sgx")]
use ekiden_runtime::common::sgx::avr::get_enclave_identity;

use crate::kdf::Kdf;

/// See `Kdf::get_or_create_keys`.
pub fn get_or_create_keys(req: &RequestIds, ctx: &mut RpcContext) -> Fallible<ContractKey> {
    // Authenticate session info (this requires all clients are SGX enclaves).
    #[cfg_attr(not(target_env = "sgx"), allow(unused))]
    let si = ctx.session_info.as_ref();

    #[cfg(target_env = "sgx")]
    let _si = si.ok_or(KeyManagerError::NotAuthenticated)?;

    // TODO: Authenticate the source enclave based on the tuple
    // (req.runtime_id, req.contract_id, si.authenticated_avr.mr_enclave)
    // so that the keys are never released to an incorrect enclave.

    Kdf::global().get_or_create_keys(req)
}

/// See `Kdf::get_public_key`.
pub fn get_public_key(
    req: &RequestIds,
    _ctx: &mut RpcContext,
) -> Fallible<Option<SignedPublicKey>> {
    let kdf = Kdf::global();
    let pk = kdf.get_public_key(req)?;
    pk.map_or(Ok(None), |pk| Ok(Some(kdf.sign_public_key(pk)?)))
}

/// See `Kdf::replicate_master_secret`.
#[cfg_attr(not(target_env = "sgx"), allow(unused))]
pub fn replicate_master_secret(
    _req: &ReplicateRequest,
    ctx: &mut RpcContext,
) -> Fallible<ReplicateResponse> {
    #[cfg(target_env = "sgx")]
    {
        can_replicate(ctx)?;
    }

    Kdf::global().replicate_master_secret()
}

#[cfg(target_env = "sgx")]
fn can_replicate(ctx: &mut RpcContext) -> Fallible<()> {
    let si = ctx.session_info.as_ref();
    let si = si.ok_or(KeyManagerError::NotAuthenticated)?;

    let their_id = &si.authenticated_avr;

    let our_id = match get_enclave_identity() {
        Some(id) => id,
        None => return Err(KeyManagerError::NotInitialized.into()),
    };

    // Always support replication to other key manager enclave instances.
    if our_id.mr_signer == their_id.mr_signer && our_id.mr_enclave == their_id.mr_enclave {
        return Ok(());
    }

    // TODO: Check the dynamic policy (for migration support).

    Err(KeyManagerError::InvalidAuthentication.into())
}
