//! Methods exported to remote clients via EnclaveRPC.
use crate::{kdf::Kdf, policy::Policy};
use anyhow::Result;
use io_context::Context;
use oasis_core_keymanager_api_common::*;
use oasis_core_runtime::{
    common::{namespace::Namespace, sgx::EnclaveIdentity},
    consensus::{beacon::EpochTime, state::beacon::ImmutableState as BeaconState},
    enclave_rpc::Context as RpcContext,
};

/// Maximum age of ephemeral key in the number of epochs.
const MAX_EPHEMERAL_KEY_AGE: EpochTime = 10;

/// See `Kdf::get_or_create_keys`.
pub fn get_or_create_keys(req: &LongTermKeyRequest, ctx: &mut RpcContext) -> Result<KeyPair> {
    authorize_private_key_generation(&req.runtime_id, ctx)?;

    Kdf::global().get_or_create_keys(req)
}

/// See `Kdf::get_public_key`.
pub fn get_public_key(
    req: &LongTermKeyRequest,
    _ctx: &mut RpcContext,
) -> Result<Option<SignedPublicKey>> {
    // No authentication or authorization.
    // Absolutely anyone is allowed to query public long-term keys.

    let kdf = Kdf::global();
    let pk = kdf.get_public_key(req)?;
    pk.map_or(Ok(None), |pk| Ok(Some(kdf.sign_public_key(pk)?)))
}

/// See `Kdf::get_or_create_keys`.
pub fn get_or_create_ephemeral_keys(
    req: &EphemeralKeyRequest,
    ctx: &mut RpcContext,
) -> Result<KeyPair> {
    authorize_private_key_generation(&req.runtime_id, ctx)?;
    validate_epoch(req.epoch, ctx)?;

    Kdf::global().get_or_create_keys(req)
}

/// See `Kdf::get_public_key`.
pub fn get_public_ephemeral_key(
    req: &EphemeralKeyRequest,
    ctx: &mut RpcContext,
) -> Result<Option<SignedPublicKey>> {
    // No authentication or authorization.
    // Absolutely anyone is allowed to query public ephemeral keys.
    validate_epoch(req.epoch, ctx)?;

    let kdf = Kdf::global();
    let pk = kdf.get_public_key(req)?;
    pk.map_or(Ok(None), |pk| Ok(Some(kdf.sign_public_key(pk)?)))
}

/// See `Kdf::replicate_master_secret`.
pub fn replicate_master_secret(
    _req: &ReplicateRequest,
    ctx: &mut RpcContext,
) -> Result<ReplicateResponse> {
    authorize_master_secret_replication(ctx)?;

    Kdf::global().replicate_master_secret()
}

/// Authorize the remote enclave so that the private keys are never released to an incorrect enclave.
fn authorize_private_key_generation(runtime_id: &Namespace, ctx: &RpcContext) -> Result<()> {
    if Policy::unsafe_skip() {
        return Ok(()); // Authorize unsafe builds always.
    }
    let remote_enclave = authenticate(ctx)?;
    Policy::global().may_get_or_create_keys(remote_enclave, runtime_id)
}

/// Authorize the remote enclave so that the master secret is never replicated to an incorrect enclave.
fn authorize_master_secret_replication(ctx: &RpcContext) -> Result<()> {
    if Policy::unsafe_skip() {
        return Ok(()); // Authorize unsafe builds always.
    }
    let remote_enclave = authenticate(ctx)?;
    Policy::global().may_replicate_master_secret(remote_enclave)
}

/// Authenticate the remote enclave based on the MRSIGNER/MRENCLAVE/request.
fn authenticate<'a>(ctx: &'a RpcContext) -> Result<&'a EnclaveIdentity> {
    let si = ctx.session_info.as_ref();
    let si = si.ok_or(KeyManagerError::NotAuthenticated)?;
    Ok(&si.verified_quote.identity)
}

// Validate that the epoch used for derivation of ephemeral private keys is not
// in the future or too far back in the past.
fn validate_epoch(epoch: EpochTime, ctx: &RpcContext) -> Result<()> {
    let consensus_state = ctx.consensus_verifier.latest_state()?;
    let beacon_state = BeaconState::new(&consensus_state);
    let consensus_epoch = beacon_state.epoch(Context::create_child(&ctx.io_ctx))?;
    if consensus_epoch < epoch || consensus_epoch > epoch + MAX_EPHEMERAL_KEY_AGE {
        return Err(KeyManagerError::InvalidEpoch.into());
    }
    Ok(())
}
