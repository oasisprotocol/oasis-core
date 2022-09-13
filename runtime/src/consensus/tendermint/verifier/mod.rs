//! Tendermint consensus layer verification logic.
use std::{convert::TryInto, str::FromStr, sync::Arc, time::Duration};

use anyhow::anyhow;
use crossbeam::channel;
use io_context::Context;
use rand::{rngs::OsRng, Rng};
use sgx_isa::Keypolicy;
use sha2::{Digest, Sha256};
use slog::{error, info};
use tendermint::merkle::HASH_SIZE;
use tendermint_light_client::{
    builder::LightClientBuilder,
    components::{self, io::AtHeight, verifier::PredicateVerifier},
    light_client,
    operations::{ProdCommitValidator, ProdHasher},
    supervisor::Instance,
    types::{
        Hash as TMHash, LightBlock as TMLightBlock, PeerId, Time, TrustThreshold, TrustedBlockState,
    },
    verifier::{predicates::ProdPredicates, Verdict, Verifier as TMVerifier},
};

use crate::{
    common::{
        crypto::signature::PublicKey,
        logger::get_logger,
        sgx::{seal, EnclaveIdentity},
        time,
        version::Version,
    },
    consensus::{
        beacon::EpochTime,
        roothash::{ComputeResultsHeader, Header, HeaderType::EpochTransition},
        state::{
            beacon::ImmutableState as BeaconState, roothash::ImmutableState as RoothashState,
            ConsensusState,
        },
        tendermint::{
            decode_light_block, encode_light_block, state_root_from_header,
            store::LruStore,
            verifier::{
                clock::InsecureClock,
                io::Io,
                types::{Command, Nonce, NONCE_SIZE},
                voting::DomSepVotingPowerCalculator,
            },
            LightBlockMeta,
        },
        transaction::{Transaction, SIGNATURE_CONTEXT},
        verifier::{self, verify_state_freshness, Error, TrustRoot, TrustedState},
        Event, LightBlock,
    },
    protocol::{Protocol, ProtocolUntrustedLocalStorage},
    storage::KeyValue,
    types::{Body, EventKind, HostFetchConsensusEventsRequest, HostFetchConsensusEventsResponse},
};

use self::{cache::Cache, handle::Handle};

// Modules.
mod cache;
mod clock;
mod handle;
mod io;
mod noop;
mod types;
mod voting;

// Re-exports.
pub use noop::NopVerifier;

/// Maximum number of times to retry initialization.
const MAX_INITIALIZATION_RETRIES: usize = 3;
/// Storage key prefix under which the sealed trusted state is stored in
/// the untrusted local storage.
///
/// The actual key includes the MRENCLAVE to support upgrades.
const TRUSTED_STATE_STORAGE_KEY_PREFIX: &str = "tendermint.verifier.trusted_state";
/// Domain separation context for the trusted state.
const TRUSTED_STATE_CONTEXT: &[u8] = b"oasis-core/verifier: trusted state";
/// Trusted state save interval (in consensus blocks).
const TRUSTED_STATE_SAVE_INTERVAL: u64 = 128;

/// Tendermint consensus layer verifier.
pub struct Verifier {
    logger: slog::Logger,
    protocol: Arc<Protocol>,
    runtime_version: Version,
    trust_root: TrustRoot,
    command_sender: channel::Sender<Command>,
    command_receiver: channel::Receiver<Command>,
}

impl Verifier {
    /// Create a new Tendermint consensus layer verifier.
    pub fn new(protocol: Arc<Protocol>, trust_root: TrustRoot) -> Self {
        let logger = get_logger("consensus/tendermint/verifier");
        let (command_sender, command_receiver) = channel::unbounded();
        let runtime_version = protocol.get_config().version;

        Self {
            logger,
            protocol,
            runtime_version,
            trust_root,
            command_sender,
            command_receiver,
        }
    }

    /// Return a handle to interact with the verifier.
    pub fn handle(&self) -> impl verifier::Verifier {
        Handle {
            protocol: self.protocol.clone(),
            command_sender: self.command_sender.clone(),
        }
    }

    fn sync(&self, cache: &mut Cache, instance: &mut Instance, height: u64) -> Result<(), Error> {
        if height < cache.last_verified_height || height < cache.latest_known_height() {
            // Ignore requests for earlier heights.
            return Ok(());
        }

        let verified_block = instance
            .light_client
            .verify_to_target(height.try_into().unwrap(), &mut instance.state)
            .map_err(|err| Error::VerificationFailed(err.into()))?;
        self.update_insecure_posix_time(&verified_block);
        cache.update_verified_block(verified_block);

        Ok(())
    }

    fn latest_consensus_state(
        &self,
        cache: &mut Cache,
        instance: &mut Instance,
    ) -> Result<ConsensusState, Error> {
        let height = cache.latest_known_height();
        self.consensus_state_at(cache, instance, height)
    }

    fn latest_consensus_height(&self, cache: &Cache) -> Result<u64, Error> {
        Ok(cache.latest_known_height())
    }

    fn consensus_state_at(
        &self,
        cache: &mut Cache,
        instance: &mut Instance,
        height: u64,
    ) -> Result<ConsensusState, Error> {
        let verified_block = instance
            .light_client
            .verify_to_target(height.try_into().unwrap(), &mut instance.state)
            .map_err(|err| Error::VerificationFailed(err.into()))?;
        let state_root = state_root_from_header(&verified_block.signed_header);

        self.update_insecure_posix_time(&verified_block);
        cache.update_verified_block(verified_block);

        Ok(ConsensusState::from_protocol(
            self.protocol.clone(),
            state_root.version + 1,
            state_root,
        ))
    }

    fn verify_consensus_only(
        &self,
        cache: &mut Cache,
        instance: &mut Instance,
        consensus_block: LightBlock,
    ) -> Result<LightBlockMeta, Error> {
        if consensus_block.height < cache.last_verified_height {
            // Ignore requests for earlier heights.
            return Err(Error::VerificationFailed(anyhow!(
                "height seems to have moved backwards"
            )));
        }

        // Decode passed block as a Tendermint block.
        let untrusted_block =
            decode_light_block(consensus_block).map_err(Error::VerificationFailed)?;
        let untrusted_header = untrusted_block
            .signed_header
            .as_ref()
            .ok_or_else(|| Error::VerificationFailed(anyhow!("missing signed header")))?;

        // Verify up to the block at current height.
        // Only does forward verification and fails if height is lower than the last trust height.
        let verified_block = instance
            .light_client
            .verify_to_target(untrusted_header.header().height, &mut instance.state)
            .map_err(|err| Error::VerificationFailed(err.into()))?;

        // Validate passed consensus block.
        if untrusted_header != &verified_block.signed_header {
            return Err(Error::VerificationFailed(anyhow!("header mismatch")));
        }

        cache.last_verified_height = verified_block.signed_header.header.height.into();
        self.update_insecure_posix_time(&verified_block);
        cache.update_verified_block(verified_block);

        Ok(untrusted_block)
    }

    /// Verify state freshness using RAK and nonces.
    fn verify_freshness_with_rak(
        &self,
        state: &ConsensusState,
        node_id: &Option<PublicKey>,
    ) -> Result<Option<PublicKey>, Error> {
        let rak = if let Some(rak) = self.protocol.get_rak() {
            rak
        } else {
            return Ok(None);
        };

        verify_state_freshness(
            state,
            rak,
            &self.trust_root.runtime_id,
            &self.runtime_version,
            node_id,
        )
    }

    /// Verify state freshness using prove freshness transaction.
    ///
    /// Verification is done in three steps. In the first one, the verifier selects a unique nonce
    /// and sends it to the host. The second step is done by the host, who prepares, signs and
    /// submits a prove freshness transaction using the received nonce. Once transaction is included
    /// in a block, the host replies with block's height, transaction details and a Merkle proof
    /// that the transaction was included in the block. In the final step, the verifier verifies
    /// the proof and accepts state as fresh iff verification succeeds.
    fn verify_freshness_with_proof(&self, instance: &mut Instance) -> Result<(), Error> {
        info!(
            self.logger,
            "Verifying state freshness using prove freshness transaction"
        );

        // Generate a random nonce for prove freshness transaction.
        let mut rng = OsRng {};
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce);

        // Ask host for freshness proof.
        let io = Io::new(&self.protocol);
        let (signed_tx, height, merkle_proof) =
            io.fetch_freshness_proof(&nonce).map_err(|err| {
                Error::FreshnessVerificationFailed(anyhow!(
                    "failed to fetch freshness proof: {}",
                    err
                ))
            })?;

        // Peek into the transaction to verify the nonce and the signature. No need to verify
        // the name of the method though.
        let tx: Transaction = cbor::from_slice(signed_tx.blob.as_slice()).map_err(|err| {
            Error::FreshnessVerificationFailed(anyhow!(
                "failed to decode prove freshness transaction: {}",
                err
            ))
        })?;
        let tx_nonce: Nonce = cbor::from_value(tx.body).map_err(|err| {
            Error::FreshnessVerificationFailed(anyhow!("failed to decode nonce: {}", err))
        })?;
        match nonce.cmp(&tx_nonce) {
            std::cmp::Ordering::Equal => (),
            _ => return Err(Error::FreshnessVerificationFailed(anyhow!("invalid nonce"))),
        }

        let chain_context = self.protocol.get_host_info().consensus_chain_context;
        let mut context = SIGNATURE_CONTEXT.to_vec();
        context.extend(chain_context.as_bytes());
        if !signed_tx.signature.verify(&context, &signed_tx.blob) {
            return Err(Error::FreshnessVerificationFailed(anyhow!(
                "failed to verify the signature"
            )));
        }

        // Fetch the block in which the transaction was published.
        let block = instance
            .light_client
            .verify_to_target(height.try_into().unwrap(), &mut instance.state)
            .map_err(|err| {
                Error::FreshnessVerificationFailed(anyhow!("failed to fetch the block: {}", err))
            })?;

        let header = block.signed_header.header;
        if header.height.value() != height {
            return Err(Error::VerificationFailed(anyhow!("invalid block")));
        }

        // Compute hash of the transaction and verify the proof.
        let digest = Sha256::digest(&cbor::to_vec(signed_tx));
        let mut tx_hash = [0u8; HASH_SIZE];
        tx_hash.copy_from_slice(&digest);

        let root_hash = header
            .data_hash
            .ok_or_else(|| Error::FreshnessVerificationFailed(anyhow!("root hash not found")))?;
        let root_hash = match root_hash {
            TMHash::Sha256(hash) => hash,
            TMHash::None => {
                return Err(Error::FreshnessVerificationFailed(anyhow!(
                    "root hash not found"
                )));
            }
        };

        merkle_proof.verify(root_hash, tx_hash).map_err(|err| {
            Error::FreshnessVerificationFailed(anyhow!("failed to verify the proof: {}", err))
        })?;

        info!(self.logger, "State freshness successfully verified");

        Ok(())
    }

    fn verify(
        &self,
        cache: &mut Cache,
        instance: &mut Instance,
        consensus_block: LightBlock,
        runtime_header: Header,
        epoch: EpochTime,
    ) -> Result<ConsensusState, Error> {
        // Verify runtime ID matches.
        if runtime_header.namespace != self.trust_root.runtime_id {
            return Err(Error::VerificationFailed(anyhow!(
                "header namespace does not match trusted runtime id"
            )));
        }

        if runtime_header.round < cache.last_verified_round {
            // Ignore requests for earlier rounds.
            return Err(Error::VerificationFailed(anyhow!(
                "round seems to have moved backwards"
            )));
        }
        if epoch < cache.last_verified_epoch {
            // Ignore requests for earlier epochs.
            return Err(Error::VerificationFailed(anyhow!(
                "epoch seems to have moved backwards"
            )));
        }

        // If round has advanced make sure that consensus height has also advanced as a round can
        // only be finalized in a subsequent consensus block. This is to avoid a situation where
        // one would keep feeding the same consensus block for subsequent rounds.
        //
        // NOTE: This needs to happen before the call to verify_consensus_only which updates the
        //       cache.last_verified_height field.
        if runtime_header.round > cache.last_verified_round
            && consensus_block.height <= cache.last_verified_height
        {
            return Err(Error::VerificationFailed(anyhow!(
                "consensus height did not advance but runtime round did"
            )));
        }

        // Verify the consensus layer block first to obtain an authoritative state root.
        let consensus_block = self.verify_consensus_only(cache, instance, consensus_block)?;
        let state_root = consensus_block.get_state_root();
        let state = ConsensusState::from_protocol(
            self.protocol.clone(),
            state_root.version + 1,
            state_root,
        );

        // Check if we have already verified this runtime header to avoid re-verification.
        if let Some(state_root) = cache.verified_state_roots.get(&runtime_header.round) {
            if state_root == &runtime_header.state_root && epoch == cache.last_verified_epoch {
                // Header and epoch matches, no need to perform re-verification.
                return Ok(state);
            }

            // Force full verification in case of cache mismatch.
        }

        // Verify that the state root matches.
        let roothash_state = RoothashState::new(&state);
        let state_root = roothash_state
            .state_root(Context::background(), self.trust_root.runtime_id)
            .map_err(|err| {
                Error::VerificationFailed(anyhow!("failed to retrieve trusted state root: {}", err))
            })?;
        if runtime_header.state_root != state_root {
            return Err(Error::VerificationFailed(anyhow!(
                "state root mismatch (expected: {} got: {})",
                state_root,
                runtime_header.state_root
            )));
        }

        // Verify that the epoch matches.
        let beacon_state = BeaconState::new(&state);
        let current_epoch = match runtime_header.header_type {
            // Query future epoch as the epoch just changed in the epoch transition block.
            EpochTransition => beacon_state
                .future_epoch(Context::background())
                .map_err(|err| {
                    Error::VerificationFailed(anyhow!("failed to retrieve future epoch: {}", err))
                }),
            _ => beacon_state.epoch(Context::background()).map_err(|err| {
                Error::VerificationFailed(anyhow!("failed to retrieve epoch: {}", err))
            }),
        }?;

        if current_epoch != epoch {
            return Err(Error::VerificationFailed(anyhow!(
                "epoch number mismatch (expected: {} got: {})",
                current_epoch,
                epoch,
            )));
        }

        // Verify our own RAK is published in registry once per epoch.
        // This ensures consensus state is recent enough.
        if cache.last_verified_epoch != epoch {
            cache.node_id = self.verify_freshness_with_rak(&state, &cache.node_id)?;
        }

        // Cache verified runtime header.
        cache
            .verified_state_roots
            .put(runtime_header.round, state_root);
        cache.last_verified_round = runtime_header.round;
        cache.last_verified_epoch = epoch;

        Ok(state)
    }

    fn verify_for_query(
        &self,
        cache: &mut Cache,
        instance: &mut Instance,
        consensus_block: LightBlock,
        runtime_header: Header,
        epoch: EpochTime,
    ) -> Result<ConsensusState, Error> {
        // Verify runtime ID matches.
        if runtime_header.namespace != self.trust_root.runtime_id {
            return Err(Error::VerificationFailed(anyhow!(
                "header namespace does not match trusted runtime id"
            )));
        }

        // Verify the consensus layer block first to obtain an authoritative state root.
        let untrusted_block =
            decode_light_block(consensus_block).map_err(Error::VerificationFailed)?;
        let untrusted_header = untrusted_block
            .signed_header
            .as_ref()
            .ok_or_else(|| Error::VerificationFailed(anyhow!("missing signed header")))?;

        // Verify up to the block at current height.
        // Only does forward verification and fails if height is lower than the last trust height.
        let verified_block = instance
            .light_client
            .verify_to_target(untrusted_header.header().height, &mut instance.state)
            .map_err(|err| Error::VerificationFailed(err.into()))?;

        // Validate passed consensus block.
        if untrusted_header != &verified_block.signed_header {
            return Err(Error::VerificationFailed(anyhow!("header mismatch")));
        }

        self.update_insecure_posix_time(&verified_block);
        cache.update_verified_block(verified_block);

        let consensus_block = untrusted_block;

        let state_root = consensus_block.get_state_root();
        let state = ConsensusState::from_protocol(
            self.protocol.clone(),
            state_root.version + 1,
            state_root,
        );

        // Check if we have already verified this runtime header to avoid re-verification.
        if let Some((state_root, state_epoch)) = cache
            .verified_state_roots_queries
            .get(&runtime_header.round)
        {
            if state_root == &runtime_header.state_root && state_epoch == &epoch {
                // Header and epoch matches, no need to perform re-verification.
                return Ok(state);
            }

            // Force full verification in case of cache mismatch.
        }

        // Verify that the state root matches.
        let roothash_state = RoothashState::new(&state);
        let state_root = roothash_state
            .state_root(Context::background(), self.trust_root.runtime_id)
            .map_err(|err| {
                Error::VerificationFailed(anyhow!("failed to retrieve trusted state root: {}", err))
            })?;

        if runtime_header.state_root != state_root {
            return Err(Error::VerificationFailed(anyhow!(
                "state root mismatch (expected: {} got: {})",
                state_root,
                runtime_header.state_root
            )));
        }

        // Verify that the epoch matches.
        let beacon_state = BeaconState::new(&state);
        let state_epoch = match runtime_header.header_type {
            // Query future epoch as the epoch just changed in the epoch transition block.
            EpochTransition => beacon_state
                .future_epoch(Context::background())
                .map_err(|err| {
                    Error::VerificationFailed(anyhow!("failed to retrieve future epoch: {}", err))
                }),
            _ => beacon_state.epoch(Context::background()).map_err(|err| {
                Error::VerificationFailed(anyhow!("failed to retrieve epoch: {}", err))
            }),
        }?;

        if state_epoch != epoch {
            return Err(Error::VerificationFailed(anyhow!(
                "epoch number mismatch (expected: {} got: {})",
                state_epoch,
                epoch,
            )));
        }

        // Cache verified runtime header.
        cache
            .verified_state_roots_queries
            .put(runtime_header.round, (state_root, state_epoch));

        Ok(state)
    }

    fn events_at(&self, height: u64, kind: EventKind) -> Result<Vec<Event>, Error> {
        let result = self
            .protocol
            .call_host(
                Context::background(),
                Body::HostFetchConsensusEventsRequest(HostFetchConsensusEventsRequest {
                    height,
                    kind,
                }),
            )
            .map_err(|err| Error::VerificationFailed(err.into()))?;
        // TODO: Perform event verification once this becomes possible.

        match result {
            Body::HostFetchConsensusEventsResponse(HostFetchConsensusEventsResponse { events }) => {
                Ok(events)
            }
            _ => Err(Error::VerificationFailed(anyhow!("bad response from host"))),
        }
    }

    fn update_insecure_posix_time(&self, verified_block: &TMLightBlock) {
        // Update untrusted time if ahead. This makes sure that the enclave's sense of time is
        // synced with consensus sense of time based on the fact that consensus time is harder to
        // fake than host operating system time.
        time::update_insecure_posix_time(
            verified_block
                .signed_header
                .header
                .time
                .duration_since(Time::unix_epoch())
                .unwrap()
                .as_secs()
                .try_into()
                .unwrap(),
        );
    }

    fn trust(&self, cache: &mut Cache, header: ComputeResultsHeader) -> Result<(), Error> {
        if let Some(state_root) = header.state_root {
            cache.verified_state_roots.put(header.round, state_root);
            cache.last_verified_round = header.round;
        }

        Ok(())
    }

    /// Start the verifier in a separate thread.
    pub fn start(self) {
        std::thread::spawn(move || {
            let logger = get_logger("consensus/tendermint/verifier");
            info!(logger, "Starting consensus verifier");

            // Try to initialize a couple of times as initially it may be the case that we have
            // started while the Runtime Host Protocol has not been fully initialized so the host
            // is still rejecting requests. This is the case because `start()` is called as part
            // of the RHP initialization itself (when handling a `RuntimeInfoRequest`).
            for retry in 1..=MAX_INITIALIZATION_RETRIES {
                // Handle panics by logging and aborting the runtime.
                let result =
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.run())) {
                        Ok(result) => result,
                        Err(_) => {
                            error!(logger, "Consensus verifier aborted");
                            std::process::abort();
                        }
                    };

                // Handle failures.
                match result {
                    Ok(_) => {}
                    Err(err @ Error::Builder(_))
                    | Err(err @ Error::TrustedStateLoadingFailed)
                    | Err(err @ Error::ChainContextTransitionFailed(_)) => {
                        error!(logger, "Consensus verifier failed to initialize, retrying";
                            "err" => %err,
                            "retry" => retry,
                        );
                    }
                    Err(err) => {
                        // All other errors are fatal.
                        error!(logger, "Consensus verifier terminated, aborting";
                            "err" => %err,
                        );
                        std::process::abort();
                    }
                }

                // Retry to initialize the verifier.
                std::thread::sleep(Duration::from_secs(1));
            }

            error!(logger, "Failed to start consensus verifier, aborting");
            std::process::abort();
        });
    }

    fn derive_trusted_state_storage_key() -> Vec<u8> {
        // Namespace storage key by MRENCLAVE as we can only unseal our own sealed data and we need
        // to support upgrades. We assume that an upgrade will include an up-to-date trusted state
        // anyway.
        format!(
            "{}.{:x}",
            TRUSTED_STATE_STORAGE_KEY_PREFIX,
            EnclaveIdentity::current()
                .map(|eid| eid.mr_enclave)
                .unwrap_or_default()
        )
        .into_bytes()
    }

    fn save_trusted_state(
        &self,
        trusted_block: &TMLightBlock,
        untrusted_local_store: &ProtocolUntrustedLocalStorage,
    ) {
        // Build trusted state.
        let trust_root = TrustRoot {
            height: trusted_block.height().into(),
            hash: trusted_block.signed_header.header.hash().to_string(),
            runtime_id: self.trust_root.runtime_id,
            chain_context: self.protocol.get_host_info().consensus_chain_context,
        };
        let lbm = LightBlockMeta {
            signed_header: Some(trusted_block.signed_header.clone()),
            validators: trusted_block.validators.clone(),
        };
        let trusted_block = Some(encode_light_block(&lbm).unwrap());
        let trusted_state = TrustedState {
            trust_root,
            trusted_block,
        };

        // Serialize and seal the trusted state.
        let raw = cbor::to_vec(trusted_state);
        let sealed = seal::seal(Keypolicy::MRENCLAVE, TRUSTED_STATE_CONTEXT, &raw);

        // Store the trusted state.
        untrusted_local_store
            .insert(Self::derive_trusted_state_storage_key(), sealed)
            .unwrap();
    }

    fn load_trusted_state(
        &self,
        untrusted_local_store: &ProtocolUntrustedLocalStorage,
    ) -> Result<TrustedState, Error> {
        // Attempt to load the previously sealed trusted state.
        let untrusted_value = untrusted_local_store
            .get(Self::derive_trusted_state_storage_key())
            .map_err(|_| Error::TrustedStateLoadingFailed)?;
        if untrusted_value.is_empty() {
            return Ok(TrustedState {
                trust_root: self.trust_root.clone(),
                trusted_block: None,
            });
        }

        // Unseal the sealed trusted state.
        let raw = seal::unseal(
            Keypolicy::MRENCLAVE,
            TRUSTED_STATE_CONTEXT,
            &untrusted_value,
        )
        .unwrap();
        let trusted_state: TrustedState =
            cbor::from_slice(&raw).expect("corrupted sealed trusted state");

        Ok(trusted_state)
    }

    fn run(&self) -> Result<(), Error> {
        // Create the untrusted local storage for storing the sealed latest trusted root.
        let untrusted_local_store =
            ProtocolUntrustedLocalStorage::new(Context::background(), self.protocol.clone());

        // Create a new light client instance.
        let options = light_client::Options {
            trust_threshold: Default::default(),
            // XXX: Until we have a way to retrieve trusted light client headers from other nodes
            //      (e.g., via EnclaveRPC) there is little sense in specifying a trusting period.
            trusting_period: Duration::from_secs(3600 * 24 * 365 * 10), // 10 years
            clock_drift: Duration::from_secs(60),
        };

        // NOTE: Peer identifier is irrelevant as the enclave is totally eclipsed.
        let peer_id = PeerId::new([0; 20]);
        let clock = Box::new(InsecureClock);
        let verifier = Box::new(PredicateVerifier::new(
            ProdPredicates::default(),
            DomSepVotingPowerCalculator,
            ProdCommitValidator::default(),
            ProdHasher::default(),
        ));
        let io = Box::new(Io::new(&self.protocol));

        // Build a light client using the embedded trust root or trust root
        // stored in the local store.
        info!(self.logger, "Loading trusted state");
        let trusted_state: TrustedState = self.load_trusted_state(&untrusted_local_store)?;

        // Verify if we can trust light blocks from a new chain if the consensus
        // chain context changes.
        info!(self.logger, "Checking chain context change");
        let trust_root = self.handle_chain_context_change(
            trusted_state,
            verifier.as_ref(),
            clock.as_ref(),
            io.as_ref(),
        )?;

        let builder = LightClientBuilder::custom(
            peer_id,
            options,
            Box::new(LruStore::new(1024)),
            io,
            Box::new(ProdHasher),
            clock,
            verifier,
            Box::new(components::scheduler::basic_bisecting_schedule),
            Box::new(ProdPredicates),
        );

        let mut instance = builder
            .trust_primary_at(
                trust_root.height.try_into().unwrap(),
                TMHash::from_str(&trust_root.hash.to_uppercase()).unwrap(),
            )
            .map_err(|err| Error::Builder(err.into()))?
            .build();

        info!(self.logger, "Consensus verifier initialized";
            "trust_root_height" => trust_root.height,
            "trust_root_hash" => ?trust_root.hash,
            "trust_root_runtime_id" => ?trust_root.runtime_id,
            "trust_root_chain_context" => ?trust_root.chain_context,
        );

        // Sync the verifier up to the latest block to make sure we are up to date before
        // processing any requests.
        let verified_block = instance
            .light_client
            .verify_to_highest(&mut instance.state)
            .map_err(|err| Error::VerificationFailed(err.into()))?;

        self.save_trusted_state(&verified_block, &untrusted_local_store);
        self.update_insecure_posix_time(&verified_block);

        let mut last_saved_verified_block_height =
            verified_block.signed_header.header.height.value();
        let mut cache = Cache::new(verified_block);

        info!(self.logger, "Consensus verifier synced";
            "latest_height" => cache.latest_known_height(),
        );

        // Verify state freshness with freshness proof. This step is required only for clients
        // as executors and key managers verify freshness regularly using node registration
        // (RAK with random nonces).
        if self.protocol.get_config().freshness_proofs {
            self.verify_freshness_with_proof(&mut instance)?;
        };

        // Start the command processing loop.
        loop {
            let command = self.command_receiver.recv().map_err(|_| Error::Internal)?;

            match command {
                Command::Synchronize(height, sender) => {
                    sender
                        .send(self.sync(&mut cache, &mut instance, height))
                        .map_err(|_| Error::Internal)?;
                }
                Command::Verify(consensus_block, runtime_header, epoch, sender, false) => {
                    sender
                        .send(self.verify(
                            &mut cache,
                            &mut instance,
                            consensus_block,
                            runtime_header,
                            epoch,
                        ))
                        .map_err(|_| Error::Internal)?;
                }
                Command::Verify(consensus_block, runtime_header, epoch, sender, true) => {
                    sender
                        .send(self.verify_for_query(
                            &mut cache,
                            &mut instance,
                            consensus_block,
                            runtime_header,
                            epoch,
                        ))
                        .map_err(|_| Error::Internal)?;
                }
                Command::Trust(header, sender) => {
                    sender
                        .send(self.trust(&mut cache, header))
                        .map_err(|_| Error::Internal)?;
                }
                Command::LatestState(sender) => {
                    sender
                        .send(self.latest_consensus_state(&mut cache, &mut instance))
                        .map_err(|_| Error::Internal)?;
                }
                Command::StateAt(height, sender) => {
                    sender
                        .send(self.consensus_state_at(&mut cache, &mut instance, height))
                        .map_err(|_| Error::Internal)?;
                }
                Command::LatestHeight(sender) => {
                    sender
                        .send(self.latest_consensus_height(&cache))
                        .map_err(|_| Error::Internal)?;
                }
                Command::EventsAt(height, kind, sender) => {
                    sender
                        .send(self.events_at(height, kind))
                        .map_err(|_| Error::Internal)?;
                }
            }

            // Persist last verified block once in a while.
            let last_height = cache.latest_known_height();
            if last_height - last_saved_verified_block_height > TRUSTED_STATE_SAVE_INTERVAL {
                self.save_trusted_state(&cache.last_verified_block, &untrusted_local_store);
                last_saved_verified_block_height = last_height;
            }
        }
    }

    fn handle_chain_context_change(
        &self,
        trusted_state: TrustedState,
        verifier: &impl TMVerifier,
        clock: &impl components::clock::Clock,
        io: &Io,
    ) -> Result<TrustRoot, Error> {
        let host_info = self.protocol.get_host_info();

        // Nothing to handle.
        if trusted_state.trust_root.chain_context == host_info.consensus_chain_context {
            info!(self.logger, "Consensus chain context hasn't changed");
            return Ok(trusted_state.trust_root);
        }
        info!(self.logger, "Consensus chain context has changed");

        // Chain context transition cannot be done directly from the embedded
        // trust root as we don't have access to the matching trusted light
        // block which validator set we need to verify blocks from the new chain.
        let trusted_block = trusted_state.trusted_block.ok_or_else(|| {
            Error::ChainContextTransitionFailed(anyhow!(
                "cannot transition from embedded trust root"
            ))
        })?;

        // Fetch genesis block from the host and prepare untrusted state for
        // verification. Since host cannot be trusted we need to verify if
        // fetched height and block belong to the genesis.
        let height = io
            .fetch_genesis_height()
            .map_err(|err| Error::ChainContextTransitionFailed(err.into()))?;
        let height = AtHeight::At(height.try_into().unwrap());
        let untrusted_block = components::io::Io::fetch_light_block(io, height)
            .map_err(|err| Error::ChainContextTransitionFailed(err.into()))?;

        if untrusted_block.signed_header.header.last_block_id.is_some() {
            return Err(Error::ChainContextTransitionFailed(anyhow!(
                "invalid genesis block"
            )));
        }

        let untrusted = untrusted_block.as_untrusted_state();

        // Prepare trusted state for verification. As we are using the verifier
        // to verify the untrusted block and state transition, we must make
        // sure that trusted and untrusted states don't belong to consecutive
        // blocks as otherwise validator set hash will get verified also.
        // Keeping heights at minimum distance of 2 will make sure that the
        // verifier will check if there is enough overlap between the validator
        // sets.
        let lbm = decode_light_block(trusted_block).map_err(Error::ChainContextTransitionFailed)?;
        let header = lbm.signed_header.unwrap().header;
        let height = header.height;
        let height = if height.increment() != untrusted.height() {
            height
        } else {
            height
                .value()
                .checked_sub(1)
                .ok_or_else(|| Error::ChainContextTransitionFailed(anyhow!("height underflow")))?
                .try_into()
                .unwrap()
        };

        let trusted = TrustedBlockState {
            header_time: header.time,
            height,
            next_validators: &lbm.validators,
            next_validators_hash: header.validators_hash,
        };

        // Verify the new block using +2/3 trust threshold rule.
        let options = light_client::Options {
            trust_threshold: TrustThreshold::TWO_THIRDS,
            trusting_period: Duration::from_secs(3600 * 24 * 365 * 10), // 10 years
            clock_drift: Duration::from_secs(60),
        };
        let now = clock.now();

        let verdict = verifier.verify(untrusted, trusted, &options, now);

        match verdict {
            Verdict::Success => (),
            Verdict::NotEnoughTrust(tally) => {
                info!(
                    self.logger,
                    "Not enough trust to accept new chain context";
                    "log_event" => "consensus/tendermint/verifier/chain_context/no_trust",
                    "tally" => ?tally,
                );
                return Err(Error::ChainContextTransitionFailed(anyhow!(
                    "not enough trust"
                )));
            }
            Verdict::Invalid(e) => {
                info!(
                    self.logger,
                    "Failed to accept new chain context";
                    "log_event" => "consensus/tendermint/verifier/chain_context/failed",
                    "error" => ?e,
                );
                return Err(Error::ChainContextTransitionFailed(anyhow!(
                    "invalid genesis block"
                )));
            }
        }

        info!(self.logger, "Consensus chain context transition done");

        let header = untrusted_block.signed_header.header;
        let trust_root = TrustRoot {
            height: header.height.into(),
            hash: header.hash().to_string(),
            runtime_id: self.trust_root.runtime_id,
            chain_context: host_info.consensus_chain_context,
        };

        Ok(trust_root)
    }
}
