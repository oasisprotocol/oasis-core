//! Methods exported to remote clients via EnclaveRPC.
use anyhow::Result;
use io_context::Context;

use oasis_core_runtime::{
    common::{namespace::Namespace, sgx::EnclaveIdentity},
    consensus::{beacon::EpochTime, state::beacon::ImmutableState as BeaconState},
    enclave_rpc::Context as RpcContext,
};

use crate::{
    api::{
        EphemeralKeyRequest, KeyManagerError, LongTermKeyRequest, ReplicateRequest,
        ReplicateResponse,
    },
    crypto::{kdf::Kdf, KeyPair, SignedPublicKey},
    policy::Policy,
};

/// Maximum age of an ephemeral key in the number of epochs.
const MAX_EPHEMERAL_KEY_AGE: EpochTime = 10;
/// Maximum age of a fresh height in the number of blocks.
///
/// A height is considered fresh if it is not more than specified amount
/// of blocks lower than the height of the latest trust root.
const MAX_FRESH_HEIGHT_AGE: u64 = 50;

/// See `Kdf::get_or_create_keys`.
pub fn get_or_create_keys(req: &LongTermKeyRequest, ctx: &mut RpcContext) -> Result<KeyPair> {
    authorize_private_key_generation(&req.runtime_id, ctx)?;
    validate_height_freshness(req.height, ctx)?;

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
    validate_height_freshness(req.height, ctx)?;

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
    req: &ReplicateRequest,
    ctx: &mut RpcContext,
) -> Result<ReplicateResponse> {
    authorize_master_secret_replication(ctx)?;
    validate_height_freshness(req.height, ctx)?;

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

/// Validate that the epoch used for derivation of ephemeral private keys is not
/// in the future or too far back in the past.
fn validate_epoch(epoch: EpochTime, ctx: &RpcContext) -> Result<()> {
    let consensus_state = ctx.consensus_verifier.latest_state()?;
    let beacon_state = BeaconState::new(&consensus_state);
    let consensus_epoch = beacon_state.epoch(Context::create_child(&ctx.io_ctx))?;
    if consensus_epoch < epoch || consensus_epoch > epoch + MAX_EPHEMERAL_KEY_AGE {
        return Err(anyhow::anyhow!(KeyManagerError::InvalidEpoch));
    }
    Ok(())
}

/// Validate that given height is fresh, i.e. the height is not more than
/// predefined number of blocks lower than the height of the latest trust root.
///
/// Key manager should use this validation to detect whether the runtimes
/// querying it have a fresh enough state.
fn validate_height_freshness(height: Option<u64>, ctx: &RpcContext) -> Result<()> {
    // Outdated key manager clients will not send height in their requests.
    // To ensure backwards compatibility we skip check in those cases.
    // This should be removed in the future by making height mandatory.
    if let Some(height) = height {
        let latest_height = ctx.consensus_verifier.latest_height()?;
        if latest_height > MAX_FRESH_HEIGHT_AGE && height < latest_height - MAX_FRESH_HEIGHT_AGE {
            return Err(anyhow::anyhow!(KeyManagerError::HeightNotFresh));
        }
    }
    Ok(())
}
