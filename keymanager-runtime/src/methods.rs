//! Methods exported to remote clients via EnclaveRPC.
use ekiden_keymanager_api::*;
use ekiden_runtime::rpc::Context as RpcContext;
use failure::Fallible;

use crate::kdf::Kdf;

// We have not implemented key-expiry yet. So give all keys the maximum expiry of 2^53-1
// because (as a convenience) that is the maximum safe number to use in JavaScript and its
// more than enough to account for enough time.
static MAX_KEY_TIMESTAMP: u64 = (1 << 53) - 1;

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
    pk.map_or(Ok(None), |pk| {
        Ok(Some(kdf.sign_public_key(pk, Some(MAX_KEY_TIMESTAMP))?))
    })
}

/// See `Kdf::get_public_key`.
pub fn get_long_term_public_key(
    req: &RequestIds,
    _ctx: &mut RpcContext,
) -> Fallible<Option<SignedPublicKey>> {
    let kdf = Kdf::global();
    let pk = kdf.get_public_key(req)?;
    pk.map_or(Ok(None), |pk| Ok(Some(kdf.sign_public_key(pk, None)?)))
}
