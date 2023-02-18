//! Methods exported to remote clients via EnclaveRPC.
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    sync::Arc,
};

use anyhow::Result;
use io_context::Context;

use oasis_core_runtime::{
    common::{
        crypto::{
            mrae::{
                deoxysii::{self, Opener},
                nonce::Nonce,
            },
            signature::{self, Signer},
            x25519,
        },
        namespace::Namespace,
        sgx::EnclaveIdentity,
    },
    consensus::{
        beacon::EpochTime,
        keymanager::{EncryptedEphemeralSecret, EncryptedSecret, SignedEncryptedEphemeralSecret},
        state::{
            beacon::ImmutableState as BeaconState, keymanager::ImmutableState as KeyManagerState,
            registry::ImmutableState as RegistryState,
        },
    },
    enclave_rpc::Context as RpcContext,
    runtime_context, BUILD_INFO,
};

use crate::{
    api::{
        EphemeralKeyRequest, GenerateEphemeralSecretRequest, GenerateEphemeralSecretResponse,
        InitRequest, InitResponse, KeyManagerError, LoadEphemeralSecretRequest, LongTermKeyRequest,
        ReplicateEphemeralSecretRequest, ReplicateEphemeralSecretResponse,
        ReplicateMasterSecretRequest, ReplicateMasterSecretResponse, SignedInitResponse,
    },
    client::{KeyManagerClient, RemoteClient},
    crypto::{
        kdf::Kdf, pack_runtime_id_epoch, unpack_encrypted_secret_nonce, KeyPair, Secret,
        SignedPublicKey, SECRET_SIZE,
    },
    policy::Policy,
    runtime::context::Context as KmContext,
};

/// Maximum age of an ephemeral key in the number of epochs.
const MAX_EPHEMERAL_KEY_AGE: EpochTime = 10;
/// Maximum age of a fresh height in the number of blocks.
///
/// A height is considered fresh if it is not more than specified amount
/// of blocks lower than the height of the latest trust root.
const MAX_FRESH_HEIGHT_AGE: u64 = 50;

/// Initialize the Kdf.
pub fn init_kdf(ctx: &mut RpcContext, req: &InitRequest) -> Result<SignedInitResponse> {
    let rctx = runtime_context!(ctx, KmContext);
    let runtime_id = rctx.runtime_id;
    let storage = ctx.untrusted_local_storage;

    let policy_checksum = Policy::global().init(ctx, &req.policy)?;

    let kdf = Kdf::global();
    kdf.set_runtime_id(runtime_id)?;

    // Load master secrets if not already loaded. It is intended that manual intervention
    // by the operator is required to remove/alter persisted secrets.
    kdf.load_master_secrets(storage, &runtime_id)?;

    // Replicate the missing secrets.
    let next_generation = kdf.next_generation();
    if !req.checksum.is_empty() && next_generation <= req.generation {
        let nodes = key_manager_nodes(ctx, runtime_id)?;
        for generation in next_generation..=req.generation {
            let secret = fetch_master_secret(ctx, generation, &nodes)?;
            kdf.add_master_secret(storage, &runtime_id, secret, generation)?;
        }
    }

    // TODO: Allow enclaves to generate master secrets for all generations.
    if req.checksum.is_empty() && kdf.next_generation() == 0 {
        // A master secret is not set, and there is no checksum in the
        // request. Either this key manager instance has never been
        // initialized, or our view of the external state is not current.
        if !req.may_generate {
            return Err(KeyManagerError::ReplicationRequired.into());
        }

        let secret = Secret::generate();
        let generation = 0;
        kdf.add_master_secret(storage, &runtime_id, secret, generation)?;
    }

    // Master secrets should now be synced unless someone did an internal state reset.
    // It is also possible that new secrets were loaded, but we don't care about any
    // of that as we always HAVE to check if the current state matches the global one.
    let (checksum, rsk) = kdf.status(&runtime_id, req.checksum.clone(), req.generation)?;

    // State is up-to-date, build the response and sign it with the RAK.
    sign_init_response(ctx, checksum, policy_checksum, rsk)
}

/// See `Kdf::get_or_create_keys`.
pub fn get_or_create_keys(ctx: &mut RpcContext, req: &LongTermKeyRequest) -> Result<KeyPair> {
    authorize_private_key_generation(ctx, &req.runtime_id)?;
    validate_height_freshness(ctx, req.height)?;

    Kdf::global().get_or_create_longterm_keys(
        ctx.untrusted_local_storage,
        req.runtime_id,
        req.key_pair_id,
        req.generation,
    )
}

/// See `Kdf::get_public_key`.
pub fn get_public_key(ctx: &mut RpcContext, req: &LongTermKeyRequest) -> Result<SignedPublicKey> {
    // No authentication or authorization.
    // Absolutely anyone is allowed to query public long-term keys.

    let kdf = Kdf::global();
    let pk = kdf.get_public_longterm_key(
        ctx.untrusted_local_storage,
        req.runtime_id,
        req.key_pair_id,
        req.generation,
    )?;
    let sig = kdf.sign_public_key(pk, req.runtime_id, req.key_pair_id, None)?;
    Ok(sig)
}

/// See `Kdf::get_or_create_ephemeral_keys`.
pub fn get_or_create_ephemeral_keys(
    ctx: &mut RpcContext,
    req: &EphemeralKeyRequest,
) -> Result<KeyPair> {
    authorize_private_key_generation(ctx, &req.runtime_id)?;
    validate_ephemeral_key_epoch(ctx, req.epoch)?;
    validate_height_freshness(ctx, req.height)?;

    Kdf::global().get_or_create_ephemeral_keys(req.runtime_id, req.key_pair_id, req.epoch)
}

/// See `Kdf::get_public_ephemeral_key`.
pub fn get_public_ephemeral_key(
    ctx: &mut RpcContext,
    req: &EphemeralKeyRequest,
) -> Result<SignedPublicKey> {
    // No authentication or authorization.
    // Absolutely anyone is allowed to query public ephemeral keys.
    validate_ephemeral_key_epoch(ctx, req.epoch)?;

    let kdf = Kdf::global();
    let pk = kdf.get_public_ephemeral_key(req.runtime_id, req.key_pair_id, req.epoch)?;
    let mut sig = kdf.sign_public_key(pk, req.runtime_id, req.key_pair_id, Some(req.epoch))?;

    // Outdated key manager clients request public ephemeral keys via secure RPC calls,
    // they never verify their signatures and are not aware that signed ephemeral keys expire.
    // To ensure backwards compatibility we clear the expiration epoch. This should be removed
    // in the future once all clients are upgraded.
    if ctx.session_info.is_some() {
        sig.expiration = None
    }

    Ok(sig)
}

/// See `Kdf::replicate_master_secret`.
pub fn replicate_master_secret(
    ctx: &mut RpcContext,
    req: &ReplicateMasterSecretRequest,
) -> Result<ReplicateMasterSecretResponse> {
    authorize_secret_replication(ctx)?;
    validate_height_freshness(ctx, req.height)?;

    let master_secret =
        Kdf::global().replicate_master_secret(ctx.untrusted_local_storage, req.generation)?;
    Ok(ReplicateMasterSecretResponse { master_secret })
}

/// See `Kdf::replicate_ephemeral_secret`.
pub fn replicate_ephemeral_secret(
    ctx: &mut RpcContext,
    req: &ReplicateEphemeralSecretRequest,
) -> Result<ReplicateEphemeralSecretResponse> {
    authorize_secret_replication(ctx)?;
    validate_height_freshness(ctx, req.height)?;

    let ephemeral_secret = Kdf::global().replicate_ephemeral_secret(req.epoch)?;
    Ok(ReplicateEphemeralSecretResponse { ephemeral_secret })
}

/// Generate an ephemeral secret and encrypt it with key manager REK keys.
pub fn generate_ephemeral_secret(
    ctx: &mut RpcContext,
    req: &GenerateEphemeralSecretRequest,
) -> Result<GenerateEphemeralSecretResponse> {
    // Allow to generate secret for the next epoch only.
    let epoch = consensus_epoch(ctx)? + 1;
    if epoch != req.epoch {
        return Err(KeyManagerError::InvalidEpoch(epoch, req.epoch).into());
    }

    // Fetch REK keys of the key manager committee members.
    let runtime_id = Kdf::global()
        .runtime_id()
        .ok_or(KeyManagerError::NotInitialized)?;
    let rek_keys = key_manager_rek_keys(ctx, runtime_id)?;
    let rek_keys: HashSet<_> = rek_keys.values().collect();

    // Abort if our REK hasn't been published.
    if rek_keys.get(&ctx.identity.public_rek()).is_none() {
        return Err(KeyManagerError::REKNotPublished.into());
    }

    // Generate a random encryption key, a random secret and encrypt the latter with REK keys.
    let priv_key = x25519::PrivateKey::generate();
    let pub_key = x25519::PublicKey::from(&priv_key);
    let mut nonce = Nonce::generate();
    let secret = Secret::generate();
    let plaintext = secret.0.to_vec();
    let additional_data = pack_runtime_id_epoch(&runtime_id, epoch);
    let mut ciphertexts = HashMap::new();
    let checksum = Kdf::checksum_ephemeral_secret(&secret, &runtime_id, epoch);

    for &rek in rek_keys.iter() {
        nonce.increment()?;

        let mut ciphertext = deoxysii::box_seal(
            &nonce,
            plaintext.clone(),
            additional_data.clone(),
            &rek.0,
            &priv_key.0,
        )?;
        ciphertext.extend_from_slice(&nonce.to_vec());

        ciphertexts.insert(*rek, ciphertext);
    }

    // Sign the secret.
    let signer: Arc<dyn Signer> = ctx.identity.clone();
    let secret = EncryptedEphemeralSecret {
        runtime_id,
        epoch,
        secret: EncryptedSecret {
            checksum,
            pub_key,
            ciphertexts,
        },
    };
    let signed_secret = SignedEncryptedEphemeralSecret::new(secret, &signer)?;

    Ok(GenerateEphemeralSecretResponse { signed_secret })
}

/// Decrypt and store an ephemeral secret. If decryption fails, try to replicate the secret
/// from another key manager enclave.
pub fn load_ephemeral_secret(ctx: &mut RpcContext, req: &LoadEphemeralSecretRequest) -> Result<()> {
    let signed_secret = validate_signed_ephemeral_secret(ctx, &req.signed_secret)?;

    let secret = match decrypt_ephemeral_secret(ctx, &signed_secret)? {
        Some(secret) => secret,
        None => {
            let nodes = nodes_with_ephemeral_secret(ctx, &signed_secret)?;
            fetch_ephemeral_secret(ctx, signed_secret.epoch, nodes)?
        }
    };

    let checksum =
        Kdf::checksum_ephemeral_secret(&secret, &signed_secret.runtime_id, signed_secret.epoch);
    if checksum != signed_secret.secret.checksum {
        return Err(KeyManagerError::EphemeralSecretChecksumMismatch.into());
    }

    Kdf::global().add_ephemeral_secret(secret, signed_secret.epoch);

    Ok(())
}

/// Decrypt ephemeral secret with local REK key.
fn decrypt_ephemeral_secret(
    ctx: &mut RpcContext,
    secret: &EncryptedEphemeralSecret,
) -> Result<Option<Secret>> {
    let epoch = secret.epoch;
    let runtime_id = secret.runtime_id;
    let rek = ctx.identity.public_rek();

    let ciphertext = match secret.secret.ciphertexts.get(&rek) {
        Some(ciphertext) => ciphertext,
        None => return Ok(None),
    };

    let (ciphertext, nonce) =
        unpack_encrypted_secret_nonce(ciphertext).ok_or(KeyManagerError::InvalidCiphertext)?;
    let additional_data = pack_runtime_id_epoch(&runtime_id, epoch);
    let plaintext = ctx.identity.box_open(
        &nonce,
        ciphertext,
        additional_data,
        &secret.secret.pub_key.0,
    )?;

    if plaintext.len() != SECRET_SIZE {
        return Err(KeyManagerError::InvalidCiphertext.into());
    }

    let secret = Secret(plaintext.try_into().expect("slice with incorrect length"));

    Ok(Some(secret))
}

/// Fetch master secret from another key manager enclave.
fn fetch_master_secret(
    ctx: &mut RpcContext,
    generation: u64,
    nodes: &Vec<signature::PublicKey>,
) -> Result<Secret> {
    let km_client = key_manager_client_for_replication(ctx);
    for node in nodes.iter() {
        km_client.set_nodes(vec![*node]);
        let result =
            km_client.replicate_master_secret(Context::create_child(&ctx.io_ctx), generation);
        let result = tokio::runtime::Handle::current().block_on(result);
        if let Ok(secret) = result {
            return Ok(secret);
        }
    }

    Err(KeyManagerError::MasterSecretNotReplicated(generation).into())
}

/// Fetch ephemeral secret from another key manager enclave.
fn fetch_ephemeral_secret(
    ctx: &mut RpcContext,
    epoch: EpochTime,
    nodes: Vec<signature::PublicKey>,
) -> Result<Secret> {
    let km_client = key_manager_client_for_replication(ctx);
    for node in nodes.iter() {
        km_client.set_nodes(vec![*node]);
        let result =
            km_client.replicate_ephemeral_secret(Context::create_child(&ctx.io_ctx), epoch);
        let result = tokio::runtime::Handle::current().block_on(result);
        if let Ok(secret) = result {
            return Ok(secret);
        }
    }

    Err(KeyManagerError::EphemeralSecretNotReplicated(epoch).into())
}

/// Key manager client for master and ephemeral secret replication.
fn key_manager_client_for_replication(ctx: &mut RpcContext) -> RemoteClient {
    let rctx = runtime_context!(ctx, KmContext);
    let protocol = rctx.protocol.clone();
    let runtime_id = rctx.runtime_id;

    RemoteClient::new_runtime_with_enclaves_and_policy(
        runtime_id,
        Some(runtime_id),
        Policy::global().may_replicate_from(),
        ctx.identity.quote_policy(),
        protocol,
        ctx.consensus_verifier.clone(),
        ctx.identity.clone(),
        1, // Not used, doesn't matter.
        vec![],
    )
}

/// Create init response and sign it with RAK.
fn sign_init_response(
    ctx: &mut RpcContext,
    checksum: Vec<u8>,
    policy_checksum: Vec<u8>,
    rsk: signature::PublicKey,
) -> Result<SignedInitResponse> {
    let is_secure = BUILD_INFO.is_secure && !Policy::unsafe_skip();
    let init_response = InitResponse {
        is_secure,
        checksum,
        policy_checksum,
        rsk,
    };
    let signer: Arc<dyn Signer> = ctx.identity.clone();
    SignedInitResponse::new(init_response, &signer)
}

/// Authorize the remote enclave so that the private keys are never released to an incorrect enclave.
fn authorize_private_key_generation(ctx: &RpcContext, runtime_id: &Namespace) -> Result<()> {
    if Policy::unsafe_skip() {
        return Ok(()); // Authorize unsafe builds always.
    }
    let remote_enclave = authenticate(ctx)?;
    Policy::global().may_get_or_create_keys(remote_enclave, runtime_id)
}

/// Authorize the remote enclave so that the master and ephemeral secrets are never replicated
/// to an incorrect enclave.
fn authorize_secret_replication(ctx: &RpcContext) -> Result<()> {
    if Policy::unsafe_skip() {
        return Ok(()); // Authorize unsafe builds always.
    }
    let remote_enclave = authenticate(ctx)?;
    Policy::global().may_replicate_secret(remote_enclave)
}

/// Authenticate the remote enclave based on the MRSIGNER/MRENCLAVE/request.
fn authenticate<'a>(ctx: &'a RpcContext) -> Result<&'a EnclaveIdentity> {
    let si = ctx.session_info.as_ref();
    let si = si.ok_or(KeyManagerError::NotAuthenticated)?;
    Ok(&si.verified_quote.identity)
}

/// Fetch current epoch from the consensus layer.
fn consensus_epoch(ctx: &RpcContext) -> Result<EpochTime> {
    let consensus_state = ctx.consensus_verifier.latest_state()?;
    let beacon_state = BeaconState::new(&consensus_state);
    let consensus_epoch = beacon_state.epoch(Context::create_child(&ctx.io_ctx))?;

    Ok(consensus_epoch)
}

/// Validate that the epoch used for derivation of ephemeral private keys is not
/// in the future or too far back in the past.
fn validate_ephemeral_key_epoch(ctx: &RpcContext, epoch: EpochTime) -> Result<()> {
    let consensus_epoch = consensus_epoch(ctx)?;
    if consensus_epoch < epoch || consensus_epoch > epoch + MAX_EPHEMERAL_KEY_AGE {
        return Err(KeyManagerError::InvalidEpoch(consensus_epoch, epoch).into());
    }
    Ok(())
}

/// Validate that given height is fresh, i.e. the height is not more than
/// predefined number of blocks lower than the height of the latest trust root.
///
/// Key manager should use this validation to detect whether the runtimes
/// querying it have a fresh enough state.
fn validate_height_freshness(ctx: &RpcContext, height: Option<u64>) -> Result<()> {
    // Outdated key manager clients will not send height in their requests.
    // To ensure backwards compatibility we skip check in those cases.
    // This should be removed in the future by making height mandatory.
    if let Some(height) = height {
        let latest_height = ctx.consensus_verifier.latest_height()?;
        if latest_height > MAX_FRESH_HEIGHT_AGE && height < latest_height - MAX_FRESH_HEIGHT_AGE {
            return Err(KeyManagerError::HeightNotFresh.into());
        }
    }
    Ok(())
}

/// Validate that the ephemeral secret has been published in the consensus layer.
fn validate_signed_ephemeral_secret(
    ctx: &RpcContext,
    signed_secret: &SignedEncryptedEphemeralSecret,
) -> Result<EncryptedEphemeralSecret> {
    let consensus_state = ctx.consensus_verifier.latest_state()?;
    let km_state = KeyManagerState::new(&consensus_state);
    let published_signed_secret = km_state
        .ephemeral_secret(
            Context::create_child(&ctx.io_ctx),
            signed_secret.secret.runtime_id,
            signed_secret.secret.epoch,
        )?
        .filter(|published_signed_secret| published_signed_secret == signed_secret)
        .ok_or(KeyManagerError::EphemeralSecretNotPublished)?;

    Ok(published_signed_secret.secret)
}

/// Fetch the identities of the key manager nodes.
fn key_manager_nodes(ctx: &RpcContext, id: Namespace) -> Result<Vec<signature::PublicKey>> {
    let consensus_state = ctx.consensus_verifier.latest_state()?;
    let km_state = KeyManagerState::new(&consensus_state);
    let status = km_state
        .status(Context::create_child(&ctx.io_ctx), id)?
        .ok_or(KeyManagerError::StatusNotFound)?;

    Ok(status.nodes)
}

/// Fetch REK keys of the key manager enclaves from the consensus layer.
fn key_manager_rek_keys(
    ctx: &RpcContext,
    id: Namespace,
) -> Result<HashMap<signature::PublicKey, x25519::PublicKey>> {
    let nodes = key_manager_nodes(ctx, id)?;

    let consensus_state = ctx.consensus_verifier.latest_state()?;
    let registry_state = RegistryState::new(&consensus_state);

    let mut rek_map = HashMap::new();
    for pk in nodes.iter() {
        let node = registry_state.node(Context::create_child(&ctx.io_ctx), pk)?;
        let runtimes = node
            .map(|n| n.runtimes)
            .unwrap_or_default()
            .unwrap_or_default();
        // Skipping version check as key managers are running exactly one version of the runtime.
        let runtime = runtimes.iter().find(|nr| nr.id == id);

        // In an SGX environment we use REK key from the consensus layer.
        #[cfg(target_env = "sgx")]
        let rek = runtime
            .map(|nr| nr.capabilities.tee.as_ref())
            .unwrap_or_default()
            .map(|c| c.rek)
            .unwrap_or_default();

        // Otherwise we use the same insecure REK key for all enclaves.
        #[cfg(not(target_env = "sgx"))]
        let rek = runtime.map(|_| ctx.identity.public_rek());

        if let Some(rek) = rek {
            rek_map.insert(*pk, rek);
        }
    }

    Ok(rek_map)
}

/// Fetch the identities of the key manager nodes that can decrypt the given ephemeral secret.
fn nodes_with_ephemeral_secret(
    ctx: &RpcContext,
    secret: &EncryptedEphemeralSecret,
) -> Result<Vec<signature::PublicKey>> {
    let rek_keys = key_manager_rek_keys(ctx, secret.runtime_id)?;
    let nodes = rek_keys
        .iter()
        .filter(|(_, rek)| secret.secret.ciphertexts.contains_key(rek))
        .map(|(&node, _)| node)
        .collect();

    Ok(nodes)
}
