//! Methods exported to remote clients via EnclaveRPC.
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    sync::Arc,
};

use anyhow::Result;

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
        keymanager::{
            EncryptedEphemeralSecret, EncryptedMasterSecret, EncryptedSecret,
            SignedEncryptedEphemeralSecret, SignedEncryptedMasterSecret,
        },
        state::{
            beacon::ImmutableState as BeaconState,
            keymanager::{ImmutableState as KeyManagerState, Status},
            registry::ImmutableState as RegistryState,
        },
        verifier::Verifier,
    },
    enclave_rpc::{
        dispatcher::{Handler, Method as RpcMethod, MethodDescriptor as RpcMethodDescriptor},
        types::Kind as RpcKind,
        Context as RpcContext,
    },
    future::block_on,
    identity::Identity,
    policy::PolicyVerifier,
    protocol::ProtocolUntrustedLocalStorage,
    Protocol, BUILD_INFO,
};

use crate::{
    api::{
        EphemeralKeyRequest, GenerateEphemeralSecretRequest, GenerateEphemeralSecretResponse,
        GenerateMasterSecretRequest, GenerateMasterSecretResponse, InitRequest, InitResponse,
        KeyManagerError, LoadEphemeralSecretRequest, LoadMasterSecretRequest, LongTermKeyRequest,
        ReplicateEphemeralSecretRequest, ReplicateEphemeralSecretResponse,
        ReplicateMasterSecretRequest, ReplicateMasterSecretResponse, SignedInitResponse,
        LOCAL_METHOD_GENERATE_EPHEMERAL_SECRET, LOCAL_METHOD_GENERATE_MASTER_SECRET,
        LOCAL_METHOD_INIT, LOCAL_METHOD_LOAD_EPHEMERAL_SECRET, LOCAL_METHOD_LOAD_MASTER_SECRET,
        METHOD_GET_OR_CREATE_EPHEMERAL_KEYS, METHOD_GET_OR_CREATE_KEYS,
        METHOD_GET_PUBLIC_EPHEMERAL_KEY, METHOD_GET_PUBLIC_KEY, METHOD_REPLICATE_EPHEMERAL_SECRET,
        METHOD_REPLICATE_MASTER_SECRET,
    },
    client::RemoteClient,
    crypto::{
        kdf::{Kdf, State},
        pack_runtime_id_epoch, pack_runtime_id_generation_epoch, unpack_encrypted_secret_nonce,
        KeyPair, Secret, SignedPublicKey, SECRET_SIZE,
    },
    policy::Policy,
    secrets::{KeyManagerSecretProvider, SecretProvider},
};

/// Maximum age of an ephemeral key in the number of epochs.
const MAX_EPHEMERAL_KEY_AGE: EpochTime = 10;
/// Maximum age of a fresh height in the number of blocks.
///
/// A height is considered fresh if it is not more than specified amount
/// of blocks lower than the height of the latest trust root.
const MAX_FRESH_HEIGHT_AGE: u64 = 50;

/// Master and ephemeral secrets RPC handler.
pub struct Secrets {
    /// Key manager runtime ID.
    pub runtime_id: Namespace,
    /// The current runtime identity if any.
    pub identity: Arc<Identity>,
    /// Consensus verifier.
    pub consensus_verifier: Arc<dyn Verifier>,
    /// Untrusted local storage.
    pub storage: Arc<ProtocolUntrustedLocalStorage>,
    /// Low-level access to the underlying Runtime Host Protocol.
    pub protocol: Arc<Protocol>,
}

impl Secrets {
    pub fn new(
        identity: Arc<Identity>,
        consensus_verifier: Arc<dyn Verifier>,
        protocol: Arc<Protocol>,
    ) -> Self {
        let storage = Arc::new(ProtocolUntrustedLocalStorage::new(protocol.clone()));
        let runtime_id = protocol.get_runtime_id();

        Self {
            runtime_id,
            identity,
            consensus_verifier,
            storage,
            protocol,
        }
    }

    /// Initialize the Kdf.
    pub fn init_kdf(&self, req: &InitRequest) -> Result<SignedInitResponse> {
        let status = req.status.clone();
        let status = self.validate_key_manager_status(status)?;

        // Empty policies are allowed only in unsafe builds.
        let policy = Policy::global();
        let policy_checksum = policy.init(&self.storage, status.policy)?;

        // Initialize or update the KDF.
        let generation = status.generation;
        let checksum = status.checksum;
        let nodes = status.nodes;
        let epoch = self.consensus_epoch()?;
        let client = self.key_manager_client_for_replication();
        let provider = KeyManagerSecretProvider::new(client, nodes);

        let kdf = Kdf::global();
        let state = kdf.init(
            &self.storage,
            self.runtime_id,
            generation,
            checksum,
            epoch,
            &provider,
        )?;

        // State is up-to-date, build the response and sign it with the RAK.
        self.sign_init_response(state, policy_checksum)
    }

    /// See `Kdf::get_or_create_keys`.
    pub fn get_or_create_keys(
        &self,
        ctx: &RpcContext,
        req: &LongTermKeyRequest,
    ) -> Result<KeyPair> {
        Self::authorize_private_key_generation(ctx, &req.runtime_id)?;
        self.validate_height_freshness(req.height)?;

        Kdf::global().get_or_create_longterm_keys(
            &self.storage,
            req.runtime_id,
            req.key_pair_id,
            req.generation,
        )
    }

    /// See `Kdf::get_public_key`.
    pub fn get_public_key(&self, req: &LongTermKeyRequest) -> Result<SignedPublicKey> {
        // No authentication or authorization.
        // Absolutely anyone is allowed to query public long-term keys.

        let kdf = Kdf::global();
        let pk = kdf.get_public_longterm_key(
            &self.storage,
            req.runtime_id,
            req.key_pair_id,
            req.generation,
        )?;
        let sig = kdf.sign_public_key(pk, req.runtime_id, req.key_pair_id, None)?;
        Ok(sig)
    }

    /// See `Kdf::get_or_create_ephemeral_keys`.
    pub fn get_or_create_ephemeral_keys(
        &self,
        ctx: &RpcContext,
        req: &EphemeralKeyRequest,
    ) -> Result<KeyPair> {
        Self::authorize_private_key_generation(ctx, &req.runtime_id)?;
        self.validate_ephemeral_key_epoch(req.epoch)?;
        self.validate_height_freshness(req.height)?;

        Kdf::global().get_or_create_ephemeral_keys(req.runtime_id, req.key_pair_id, req.epoch)
    }

    /// See `Kdf::get_public_ephemeral_key`.
    pub fn get_public_ephemeral_key(&self, req: &EphemeralKeyRequest) -> Result<SignedPublicKey> {
        // No authentication or authorization.
        // Absolutely anyone is allowed to query public ephemeral keys.
        self.validate_ephemeral_key_epoch(req.epoch)?;

        let kdf = Kdf::global();
        let pk = kdf.get_public_ephemeral_key(req.runtime_id, req.key_pair_id, req.epoch)?;
        let sig = kdf.sign_public_key(pk, req.runtime_id, req.key_pair_id, Some(req.epoch))?;

        Ok(sig)
    }

    /// See `Kdf::replicate_master_secret`.
    pub fn replicate_master_secret(
        &self,
        ctx: &RpcContext,
        req: &ReplicateMasterSecretRequest,
    ) -> Result<ReplicateMasterSecretResponse> {
        Self::authorize_secret_replication(ctx)?;
        self.validate_height_freshness(req.height)?;

        let master_secret = Kdf::global().replicate_master_secret(&self.storage, req.generation)?;
        let checksum = Kdf::load_checksum(&self.storage, req.generation);

        Ok(ReplicateMasterSecretResponse {
            master_secret,
            checksum,
        })
    }

    /// See `Kdf::replicate_ephemeral_secret`.
    pub fn replicate_ephemeral_secret(
        &self,
        ctx: &RpcContext,
        req: &ReplicateEphemeralSecretRequest,
    ) -> Result<ReplicateEphemeralSecretResponse> {
        Self::authorize_secret_replication(ctx)?;
        self.validate_height_freshness(req.height)?;

        let ephemeral_secret = Kdf::global().replicate_ephemeral_secret(req.epoch)?;
        Ok(ReplicateEphemeralSecretResponse { ephemeral_secret })
    }

    /// Generate a master secret and encrypt it using the key manager's REK keys.
    pub fn generate_master_secret(
        &self,
        req: &GenerateMasterSecretRequest,
    ) -> Result<GenerateMasterSecretResponse> {
        let kdf = Kdf::global();
        let runtime_id = kdf.runtime_id()?;

        // Allow generating a secret for the next epoch only.
        let epoch = self.consensus_epoch()? + 1;
        if epoch != req.epoch {
            return Err(KeyManagerError::InvalidEpoch(epoch, req.epoch).into());
        }

        // Generate a secret and encrypt it.
        // Note that the checksum can be computed for the next generation only.
        let generation = req.generation;
        let secret = Secret::generate();
        let checksum = kdf.checksum_master_secret_proposal(runtime_id, &secret, generation)?;
        let additional_data = pack_runtime_id_generation_epoch(&runtime_id, generation, epoch);
        let secret = self.encrypt_secret(secret, checksum, additional_data, runtime_id)?;

        // Sign the secret.
        let signer: Arc<dyn Signer> = self.identity.clone();
        let secret = EncryptedMasterSecret {
            runtime_id,
            generation,
            epoch,
            secret,
        };
        let signed_secret = SignedEncryptedMasterSecret::new(secret, &signer)?;

        Ok(GenerateMasterSecretResponse { signed_secret })
    }

    /// Generate an ephemeral secret and encrypt it using the key manager's REK keys.
    pub fn generate_ephemeral_secret(
        &self,
        req: &GenerateEphemeralSecretRequest,
    ) -> Result<GenerateEphemeralSecretResponse> {
        let kdf = Kdf::global();
        let runtime_id = kdf.runtime_id()?;

        // Allow generating a secret for the next epoch only.
        let epoch = self.consensus_epoch()? + 1;
        if epoch != req.epoch {
            return Err(KeyManagerError::InvalidEpoch(epoch, req.epoch).into());
        }

        // Generate a secret and encrypt it.
        let secret = Secret::generate();
        let checksum = Kdf::checksum_ephemeral_secret(&runtime_id, &secret, epoch);
        let additional_data = pack_runtime_id_epoch(&runtime_id, epoch);
        let secret = self.encrypt_secret(secret, checksum, additional_data, runtime_id)?;

        // Sign the secret.
        let signer: Arc<dyn Signer> = self.identity.clone();
        let secret = EncryptedEphemeralSecret {
            runtime_id,
            epoch,
            secret,
        };
        let signed_secret = SignedEncryptedEphemeralSecret::new(secret, &signer)?;

        Ok(GenerateEphemeralSecretResponse { signed_secret })
    }

    /// Encrypt a secret using the Deoxys-II MRAE algorithm and the key manager's REK keys.
    fn encrypt_secret(
        &self,
        secret: Secret,
        checksum: Vec<u8>,
        additional_data: Vec<u8>,
        runtime_id: Namespace,
    ) -> Result<EncryptedSecret> {
        // Fetch REK keys of the key manager committee members.
        let rek_keys = self.key_manager_rek_keys(runtime_id)?;
        let rek_keys: HashSet<_> = rek_keys.values().collect();
        // Abort if our REK hasn't been published.
        if rek_keys.get(&self.identity.public_rek()).is_none() {
            return Err(KeyManagerError::REKNotPublished.into());
        }
        // Encrypt the secret.
        let priv_key = x25519::PrivateKey::generate();
        let pub_key = x25519::PublicKey::from(&priv_key);
        let mut nonce = Nonce::generate();
        let plaintext = secret.0.to_vec();
        let mut ciphertexts = HashMap::new();
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

        Ok(EncryptedSecret {
            checksum,
            pub_key,
            ciphertexts,
        })
    }

    /// Decrypt and store a proposal for the next master secret.
    pub fn load_master_secret(&self, req: &LoadMasterSecretRequest) -> Result<()> {
        let signed_secret = self.validate_signed_master_secret(&req.signed_secret)?;

        let secret = match self.decrypt_master_secret(&signed_secret)? {
            Some(secret) => secret,
            None => return Ok(()),
        };

        Kdf::global().add_master_secret_proposal(
            &self.storage,
            &signed_secret.runtime_id,
            secret,
            signed_secret.generation,
            &signed_secret.secret.checksum,
        )
    }

    /// Decrypt and store an ephemeral secret. If decryption fails, try to replicate the secret
    /// from another key manager enclave.
    pub fn load_ephemeral_secret(&self, req: &LoadEphemeralSecretRequest) -> Result<()> {
        let signed_secret = self.validate_signed_ephemeral_secret(&req.signed_secret)?;

        let secret = match self.decrypt_ephemeral_secret(&signed_secret)? {
            Some(secret) => secret,
            None => {
                let nodes = self.nodes_with_ephemeral_secret(&signed_secret)?;
                let client = self.key_manager_client_for_replication();

                KeyManagerSecretProvider::new(client, nodes)
                    .ephemeral_secret_iter(signed_secret.epoch)
                    .find(|secret| {
                        let checksum = Kdf::checksum_ephemeral_secret(
                            &signed_secret.runtime_id,
                            secret,
                            signed_secret.epoch,
                        );
                        checksum == signed_secret.secret.checksum
                    })
                    .ok_or(KeyManagerError::EphemeralSecretNotReplicated(
                        signed_secret.epoch,
                    ))?
            }
        };

        Kdf::global().add_ephemeral_secret(
            &signed_secret.runtime_id,
            secret,
            signed_secret.epoch,
            &signed_secret.secret.checksum,
        )
    }

    /// Decrypt master secret with local REK key.
    fn decrypt_master_secret(&self, secret: &EncryptedMasterSecret) -> Result<Option<Secret>> {
        let generation = secret.generation;
        let epoch = secret.epoch;
        let runtime_id = secret.runtime_id;
        let rek = self.identity.public_rek();

        let ciphertext = match secret.secret.ciphertexts.get(&rek) {
            Some(ciphertext) => ciphertext,
            None => return Ok(None),
        };

        let (ciphertext, nonce) =
            unpack_encrypted_secret_nonce(ciphertext).ok_or(KeyManagerError::InvalidCiphertext)?;
        let additional_data = pack_runtime_id_generation_epoch(&runtime_id, generation, epoch);
        let plaintext = self.identity.box_open(
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

    /// Decrypt ephemeral secret with local REK key.
    fn decrypt_ephemeral_secret(
        &self,
        secret: &EncryptedEphemeralSecret,
    ) -> Result<Option<Secret>> {
        let epoch = secret.epoch;
        let runtime_id = secret.runtime_id;
        let rek = self.identity.public_rek();

        let ciphertext = match secret.secret.ciphertexts.get(&rek) {
            Some(ciphertext) => ciphertext,
            None => return Ok(None),
        };

        let (ciphertext, nonce) =
            unpack_encrypted_secret_nonce(ciphertext).ok_or(KeyManagerError::InvalidCiphertext)?;
        let additional_data = pack_runtime_id_epoch(&runtime_id, epoch);
        let plaintext = self.identity.box_open(
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

    /// Key manager client for master and ephemeral secret replication.
    fn key_manager_client_for_replication(&self) -> RemoteClient {
        RemoteClient::new_runtime_with_enclaves_and_policy(
            self.runtime_id,
            Some(self.runtime_id),
            Policy::global().may_replicate_from(),
            self.identity.quote_policy(),
            self.protocol.clone(),
            self.consensus_verifier.clone(),
            self.identity.clone(),
            1, // Not used, doesn't matter.
            vec![],
        )
    }

    /// Create init response and sign it with RAK.
    fn sign_init_response(
        &self,
        state: State,
        policy_checksum: Vec<u8>,
    ) -> Result<SignedInitResponse> {
        let is_secure = BUILD_INFO.is_secure && !Policy::unsafe_skip();
        let init_response = InitResponse {
            is_secure,
            checksum: state.checksum,
            next_checksum: state.next_checksum,
            policy_checksum,
            rsk: state.signing_key,
            next_rsk: state.next_signing_key,
        };
        let signer: Arc<dyn Signer> = self.identity.clone();
        SignedInitResponse::new(init_response, &signer)
    }

    /// Authorize the remote enclave so that the private keys are never released to an incorrect enclave.
    fn authorize_private_key_generation(ctx: &RpcContext, runtime_id: &Namespace) -> Result<()> {
        if Policy::unsafe_skip() {
            return Ok(()); // Authorize unsafe builds always.
        }
        let remote_enclave = Self::authenticate(ctx)?;
        Policy::global().may_get_or_create_keys(remote_enclave, runtime_id)
    }

    /// Authorize the remote enclave so that the master and ephemeral secrets are never replicated
    /// to an incorrect enclave.
    fn authorize_secret_replication(ctx: &RpcContext) -> Result<()> {
        if Policy::unsafe_skip() {
            return Ok(()); // Authorize unsafe builds always.
        }
        let remote_enclave = Self::authenticate(ctx)?;
        Policy::global().may_replicate_secret(remote_enclave)
    }

    /// Authenticate the remote enclave based on the MRSIGNER/MRENCLAVE/request.
    fn authenticate(ctx: &RpcContext) -> Result<&EnclaveIdentity> {
        let si = ctx.session_info.as_ref();
        let si = si.ok_or(KeyManagerError::NotAuthenticated)?;
        Ok(&si.verified_quote.identity)
    }

    /// Fetch current epoch from the consensus layer.
    fn consensus_epoch(&self) -> Result<EpochTime> {
        let consensus_state = block_on(self.consensus_verifier.latest_state())?;
        let beacon_state = BeaconState::new(&consensus_state);
        let consensus_epoch = beacon_state.epoch()?;

        Ok(consensus_epoch)
    }

    /// Verify that the key manager status has been published in the consensus layer.
    fn validate_key_manager_status(&self, status: Status) -> Result<Status> {
        let consensus_verifier = self.consensus_verifier.clone();
        let verifier = PolicyVerifier::new(consensus_verifier);

        verifier.verify_key_manager_status(status, self.runtime_id)
    }

    /// Validate that the epoch used for derivation of ephemeral private keys is not
    /// in the future or too far back in the past.
    fn validate_ephemeral_key_epoch(&self, epoch: EpochTime) -> Result<()> {
        let consensus_epoch = self.consensus_epoch()?;
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
    fn validate_height_freshness(&self, height: Option<u64>) -> Result<()> {
        // Outdated key manager clients will not send height in their requests.
        // To ensure backwards compatibility we skip check in those cases.
        // This should be removed in the future by making height mandatory.
        if let Some(height) = height {
            let latest_height = block_on(self.consensus_verifier.latest_height())?;
            if latest_height > MAX_FRESH_HEIGHT_AGE && height < latest_height - MAX_FRESH_HEIGHT_AGE
            {
                return Err(KeyManagerError::HeightNotFresh.into());
            }
        }
        Ok(())
    }

    /// Verify that the master secret has been published in the consensus layer.
    fn validate_signed_master_secret(
        &self,
        signed_secret: &SignedEncryptedMasterSecret,
    ) -> Result<EncryptedMasterSecret> {
        let consensus_state = block_on(self.consensus_verifier.latest_state())?;
        let km_state = KeyManagerState::new(&consensus_state);
        let published_signed_secret = km_state
            .master_secret(signed_secret.secret.runtime_id)?
            .filter(|published_signed_secret| published_signed_secret == signed_secret)
            .ok_or(KeyManagerError::MasterSecretNotPublished)?;

        Ok(published_signed_secret.secret)
    }

    /// Validate that the ephemeral secret has been published in the consensus layer.
    fn validate_signed_ephemeral_secret(
        &self,
        signed_secret: &SignedEncryptedEphemeralSecret,
    ) -> Result<EncryptedEphemeralSecret> {
        let consensus_state = block_on(self.consensus_verifier.latest_state())?;
        let km_state = KeyManagerState::new(&consensus_state);
        let published_signed_secret = km_state
            .ephemeral_secret(signed_secret.secret.runtime_id)?
            .filter(|published_signed_secret| published_signed_secret == signed_secret)
            .ok_or(KeyManagerError::EphemeralSecretNotPublished)?;

        Ok(published_signed_secret.secret)
    }

    /// Fetch the identities of the key manager nodes.
    fn key_manager_nodes(&self, id: Namespace) -> Result<Vec<signature::PublicKey>> {
        let consensus_state = block_on(self.consensus_verifier.latest_state())?;
        let km_state = KeyManagerState::new(&consensus_state);
        let status = km_state
            .status(id)?
            .ok_or(KeyManagerError::StatusNotFound)?;

        Ok(status.nodes)
    }

    /// Fetch REK keys of the key manager enclaves from the consensus layer.
    fn key_manager_rek_keys(
        &self,
        id: Namespace,
    ) -> Result<HashMap<signature::PublicKey, x25519::PublicKey>> {
        let nodes = self.key_manager_nodes(id)?;

        let consensus_state = block_on(self.consensus_verifier.latest_state())?;
        let registry_state = RegistryState::new(&consensus_state);

        let mut rek_map = HashMap::new();
        for pk in nodes.iter() {
            let node = registry_state.node(pk)?;
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
            let rek = runtime.map(|_| self.identity.public_rek());

            if let Some(rek) = rek {
                rek_map.insert(*pk, rek);
            }
        }

        Ok(rek_map)
    }

    /// Fetch the identities of the key manager nodes that can decrypt the given ephemeral secret.
    fn nodes_with_ephemeral_secret(
        &self,
        secret: &EncryptedEphemeralSecret,
    ) -> Result<Vec<signature::PublicKey>> {
        let rek_keys = self.key_manager_rek_keys(secret.runtime_id)?;
        let nodes = rek_keys
            .iter()
            .filter(|(_, rek)| secret.secret.ciphertexts.contains_key(rek))
            .map(|(&node, _)| node)
            .collect();

        Ok(nodes)
    }
}

impl Handler for Secrets {
    fn methods(&'static self) -> Vec<RpcMethod> {
        vec![
            // Register RPC methods exposed via EnclaveRPC to remote clients.
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_GET_OR_CREATE_KEYS.to_string(),
                    kind: RpcKind::NoiseSession,
                },
                move |ctx: &_, req: &_| self.get_or_create_keys(ctx, req),
            ),
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_GET_PUBLIC_KEY.to_string(),
                    kind: RpcKind::InsecureQuery,
                },
                move |_ctx: &_, req: &_| self.get_public_key(req),
            ),
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_GET_OR_CREATE_EPHEMERAL_KEYS.to_string(),
                    kind: RpcKind::NoiseSession,
                },
                move |ctx: &_, req: &_| self.get_or_create_ephemeral_keys(ctx, req),
            ),
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_GET_PUBLIC_EPHEMERAL_KEY.to_string(),
                    kind: RpcKind::InsecureQuery,
                },
                move |_ctx: &_, req: &_| self.get_public_ephemeral_key(req),
            ),
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_REPLICATE_MASTER_SECRET.to_string(),
                    kind: RpcKind::NoiseSession,
                },
                move |ctx: &_, req: &_| self.replicate_master_secret(ctx, req),
            ),
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_REPLICATE_EPHEMERAL_SECRET.to_string(),
                    kind: RpcKind::NoiseSession,
                },
                move |ctx: &_, req: &_| self.replicate_ephemeral_secret(ctx, req),
            ),
            // Register local methods, for use by the node key manager component.
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: LOCAL_METHOD_INIT.to_string(),
                    kind: RpcKind::LocalQuery,
                },
                move |_ctx: &_, req: &_| self.init_kdf(req),
            ),
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: LOCAL_METHOD_GENERATE_MASTER_SECRET.to_string(),
                    kind: RpcKind::LocalQuery,
                },
                move |_ctx: &_, req: &_| self.generate_master_secret(req),
            ),
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: LOCAL_METHOD_GENERATE_EPHEMERAL_SECRET.to_string(),
                    kind: RpcKind::LocalQuery,
                },
                move |_ctx: &_, req: &_| self.generate_ephemeral_secret(req),
            ),
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: LOCAL_METHOD_LOAD_MASTER_SECRET.to_string(),
                    kind: RpcKind::LocalQuery,
                },
                move |_ctx: &_, req: &_| self.load_master_secret(req),
            ),
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: LOCAL_METHOD_LOAD_EPHEMERAL_SECRET.to_string(),
                    kind: RpcKind::LocalQuery,
                },
                move |_ctx: &_, req: &_| self.load_ephemeral_secret(req),
            ),
        ]
    }
}
