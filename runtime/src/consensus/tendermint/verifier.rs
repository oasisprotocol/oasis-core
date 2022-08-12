//! Tendermint consensus layer verification logic.
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::anyhow;
use crossbeam::channel;
use io_context::Context;
use sgx_isa::Keypolicy;
use slog::{error, info};
use tendermint::{
    block::CommitSig,
    vote::{SignedVote, ValidatorIndex, Vote},
};
use tendermint_light_client::{
    builder::LightClientBuilder,
    components::{self, verifier::PredicateVerifier},
    light_client,
    operations::{ProdCommitValidator, ProdHasher, VotingPowerCalculator, VotingPowerTally},
    supervisor::Instance,
    types::{
        Commit, Hash as TMHash, LightBlock as TMLightBlock, PeerId, SignedHeader, Time,
        TrustThreshold, ValidatorSet,
    },
    verifier::{errors::VerificationError, predicates::ProdPredicates},
};
use tendermint_rpc::error::Error as RpcError;

use super::store::LruStore;
use crate::{
    common::{
        crypto::{hash::Hash, signature::PublicKey},
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
            decode_light_block, state_root_from_header, LightBlockMeta, TENDERMINT_CONTEXT,
        },
        verifier::{self, verify_state_freshness, Error, TrustRoot},
        LightBlock, HEIGHT_LATEST,
    },
    protocol::{Protocol, ProtocolUntrustedLocalStorage},
    storage::KeyValue,
    types::Body,
};

/// Maximum number of times to retry initialization.
const MAX_INITIALIZATION_RETRIES: usize = 3;
/// Storage key prefix under which the sealed trust root is stored in untrusted local storage.
///
/// The actual key includes the MRENCLAVE to support upgrades.
const TRUST_ROOT_STORAGE_KEY_PREFIX: &str = "tendermint.verifier.trust_root";
/// Domain separation context for the trust root.
const TRUST_ROOT_CONTEXT: &[u8] = b"oasis-core/verifier: trust root";
/// Trust root save interval (in consensus blocks).
const TRUST_ROOT_SAVE_INTERVAL: u64 = 128;

/// A verifier which performs no verification.
pub struct NopVerifier {
    protocol: Arc<Protocol>,
}

impl NopVerifier {
    /// Create a new non-verifying verifier.
    pub fn new(protocol: Arc<Protocol>) -> Self {
        Self { protocol }
    }
}

impl verifier::Verifier for NopVerifier {
    fn sync(&self, _height: u64) -> Result<(), Error> {
        Ok(())
    }

    fn verify(
        &self,
        consensus_block: LightBlock,
        _runtime_header: Header,
        _epoch: EpochTime,
    ) -> Result<ConsensusState, Error> {
        self.unverified_state(consensus_block)
    }

    fn verify_for_query(
        &self,
        consensus_block: LightBlock,
        _runtime_header: Header,
        _epoch: EpochTime,
    ) -> Result<ConsensusState, Error> {
        self.unverified_state(consensus_block)
    }

    fn unverified_state(&self, consensus_block: LightBlock) -> Result<ConsensusState, Error> {
        let untrusted_block =
            decode_light_block(consensus_block).map_err(Error::VerificationFailed)?;
        // NOTE: No actual verification is performed.
        let state_root = untrusted_block.get_state_root();
        Ok(ConsensusState::from_protocol(
            self.protocol.clone(),
            state_root,
        ))
    }

    fn latest_state(&self) -> Result<ConsensusState, Error> {
        let result = self
            .protocol
            .call_host(
                Context::background(),
                Body::HostFetchConsensusBlockRequest {
                    height: HEIGHT_LATEST,
                },
            )
            .map_err(|err| Error::VerificationFailed(err.into()))?;

        let block = match result {
            Body::HostFetchConsensusBlockResponse { block } => block,
            _ => return Err(Error::VerificationFailed(anyhow!("bad response from host"))),
        };

        self.unverified_state(block)
    }

    fn trust(&self, _header: &ComputeResultsHeader) -> Result<(), Error> {
        Ok(())
    }
}

enum Command {
    Synchronize(u64, channel::Sender<Result<(), Error>>),
    Verify(
        LightBlock,
        Header,
        EpochTime,
        channel::Sender<Result<ConsensusState, Error>>,
        bool,
    ),
    Trust(ComputeResultsHeader, channel::Sender<Result<(), Error>>),
    LatestState(channel::Sender<Result<ConsensusState, Error>>),
}

/// Tendermint consensus layer verifier.
pub struct Verifier {
    protocol: Arc<Protocol>,
    runtime_version: Version,
    trust_root: TrustRoot,
    command_sender: channel::Sender<Command>,
    command_receiver: channel::Receiver<Command>,
}

struct Cache {
    last_verified_height: u64,
    last_verified_round: u64,
    last_verified_epoch: u64,
    last_trust_root: TrustRoot,
    verified_state_roots: lru::LruCache<u64, Hash>,
    verified_state_roots_queries: lru::LruCache<u64, (Hash, u64)>,
    node_id: Option<PublicKey>,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            last_verified_height: 0,
            last_verified_round: 0,
            last_verified_epoch: 0,
            last_trust_root: TrustRoot::default(),
            verified_state_roots: lru::LruCache::new(128),
            verified_state_roots_queries: lru::LruCache::new(128),
            node_id: None,
        }
    }
}

impl Cache {
    /// Latest known and verified consensus layer height.
    fn latest_known_height(&self) -> u64 {
        self.last_trust_root.height
    }

    /// Process a new verified consensus layer block and update the cache if needed.
    fn update_verified_block(&mut self, verified_block: &TMLightBlock) {
        let header = &verified_block.signed_header.header;
        let height = header.height.into();

        // Update the trust root if ahead.
        if height > self.last_trust_root.height {
            self.last_trust_root.height = height;
            self.last_trust_root.hash = header.hash().to_string();
        }
    }
}

impl Verifier {
    /// Create a new Tendermint consensus layer verifier.
    pub fn new(protocol: Arc<Protocol>, trust_root: TrustRoot) -> Self {
        let (command_sender, command_receiver) = channel::unbounded();
        let runtime_version = protocol.get_config().version;

        Self {
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
        cache.update_verified_block(&verified_block);

        Ok(())
    }

    fn latest_consensus_state(
        &self,
        cache: &Cache,
        instance: &mut Instance,
    ) -> Result<ConsensusState, Error> {
        let height = cache.latest_known_height();
        let verified_block = instance
            .light_client
            .verify_to_target(height.try_into().unwrap(), &mut instance.state)
            .map_err(|err| Error::VerificationFailed(err.into()))?;
        // No need to update time as this has already been done once for this height.

        let state_root = state_root_from_header(&verified_block.signed_header);
        Ok(ConsensusState::from_protocol(
            self.protocol.clone(),
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
        self.update_insecure_posix_time(&verified_block);
        cache.update_verified_block(&verified_block);

        // Validate passed consensus block.
        if untrusted_header != &verified_block.signed_header {
            return Err(Error::VerificationFailed(anyhow!("header mismatch")));
        }

        cache.last_verified_height = verified_block.signed_header.header.height.into();

        Ok(untrusted_block)
    }

    fn verify_freshness(
        &self,
        state: &ConsensusState,
        node_id: &Option<PublicKey>,
    ) -> Result<Option<PublicKey>, Error> {
        let rak = if let Some(rak) = self.protocol.get_rak() {
            rak
        } else {
            return Ok(None);
        };

        verify_state_freshness(state, &self.trust_root, rak, &self.runtime_version, node_id)
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
        let state = ConsensusState::from_protocol(self.protocol.clone(), state_root);

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
            cache.node_id = self.verify_freshness(&state, &cache.node_id)?;
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
        self.update_insecure_posix_time(&verified_block);
        cache.update_verified_block(&verified_block);

        // Validate passed consensus block.
        if untrusted_header != &verified_block.signed_header {
            return Err(Error::VerificationFailed(anyhow!("header mismatch")));
        }
        let consensus_block = untrusted_block;

        let state =
            ConsensusState::from_protocol(self.protocol.clone(), consensus_block.get_state_root());

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
                match self.run() {
                    Ok(_) => {}
                    Err(err @ Error::Builder(_)) | Err(err @ Error::TrustRootLoadingFailed) => {
                        error!(logger, "Consensus verifier failed to initialize, retrying";
                            "err" => %err,
                            "retry" => retry,
                        );
                    }
                    Err(err) => {
                        // All other errors are fatal.
                        error!(logger, "Consensus verifier terminated";
                            "err" => %err,
                        );
                        return;
                    }
                }

                // Retry to initialize the verifier.
                std::thread::sleep(Duration::from_secs(1));
            }
        });
    }

    fn derive_trust_root_storage_key() -> Vec<u8> {
        // Namespace storage key by MRENCLAVE as we can only unseal our own sealed data and we need
        // to support upgrades. We assume that an upgrade will include an up-to-date trust root
        // anyway.
        format!(
            "{}.{:x}",
            TRUST_ROOT_STORAGE_KEY_PREFIX,
            EnclaveIdentity::current()
                .map(|eid| eid.mr_enclave)
                .unwrap_or_default()
        )
        .into_bytes()
    }

    fn load_trust_root(
        &self,
        untrusted_local_store: &ProtocolUntrustedLocalStorage,
    ) -> Result<TrustRoot, Error> {
        // Attempt to load the previously sealed trust root.
        let untrusted_value = untrusted_local_store
            .get(Self::derive_trust_root_storage_key())
            .map_err(|_| Error::TrustRootLoadingFailed)?;
        if untrusted_value.is_empty() {
            // No previously stored trust root is available, use the embedded root.
            return Ok(self.trust_root.clone());
        }

        // Unseal the sealed trust root.
        let raw = seal::unseal(Keypolicy::MRENCLAVE, TRUST_ROOT_CONTEXT, &untrusted_value).unwrap();
        let trust_root: TrustRoot = cbor::from_slice(&raw).expect("corrupted sealed trust root");

        // Make sure that the loaded trust root is not older than the embedded root.
        if trust_root.height <= self.trust_root.height {
            return Ok(self.trust_root.clone());
        }
        Ok(trust_root)
    }

    fn save_trust_root(
        &self,
        untrusted_local_store: &ProtocolUntrustedLocalStorage,
        cache: &Cache,
    ) {
        // Serialize and seal the trust root.
        let raw = cbor::to_vec(cache.last_trust_root.clone());
        let sealed = seal::seal(Keypolicy::MRENCLAVE, TRUST_ROOT_CONTEXT, &raw);

        // Store the trust root.
        untrusted_local_store
            .insert(Self::derive_trust_root_storage_key(), sealed)
            .unwrap();
    }

    fn run(&self) -> Result<(), Error> {
        let logger = get_logger("consensus/tendermint/verifier");

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
        let builder = LightClientBuilder::custom(
            peer_id,
            options,
            Box::new(LruStore::new(1024)),
            Box::new(Io::new(&self.protocol)),
            Box::new(ProdHasher),
            Box::new(InsecureClock),
            Box::new(PredicateVerifier::new(
                ProdPredicates::default(),
                DomSepVotingPowerCalculator,
                ProdCommitValidator::default(),
                ProdHasher::default(),
            )),
            Box::new(components::scheduler::basic_bisecting_schedule),
            Box::new(ProdPredicates),
        );
        let trust_root = self.load_trust_root(&untrusted_local_store)?;
        let mut instance = builder
            .trust_primary_at(
                trust_root.height.try_into().unwrap(),
                TMHash::from_str(&trust_root.hash.to_uppercase()).unwrap(),
            )
            .map_err(|err| Error::Builder(err.into()))?
            .build();

        info!(logger, "Consensus verifier initialized";
            "trust_root_height" => trust_root.height,
            "trust_root_hash" => ?trust_root.hash,
            "trust_root_runtime_id" => ?trust_root.runtime_id,
        );

        let mut last_saved_trust_root_height = trust_root.height;
        let mut cache = Cache {
            last_trust_root: trust_root,
            ..Default::default()
        };

        // Sync the verifier up to the latest block to make sure we are up to date before
        // processing any requests.
        let verified_block = instance
            .light_client
            .verify_to_highest(&mut instance.state)
            .map_err(|err| Error::VerificationFailed(err.into()))?;
        self.update_insecure_posix_time(&verified_block);
        cache.update_verified_block(&verified_block);
        self.save_trust_root(&untrusted_local_store, &cache);

        info!(logger, "Consensus verifier synced";
            "latest_height" => cache.latest_known_height(),
        );

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
                        .send(self.latest_consensus_state(&cache, &mut instance))
                        .map_err(|_| Error::Internal)?;
                }
            }

            // Persist trusted root every once in a while.
            if cache.last_trust_root.height - last_saved_trust_root_height
                > TRUST_ROOT_SAVE_INTERVAL
            {
                self.save_trust_root(&untrusted_local_store, &cache);
                last_saved_trust_root_height = cache.last_trust_root.height;
            }
        }
    }
}

struct Handle {
    protocol: Arc<Protocol>,
    command_sender: channel::Sender<Command>,
}

impl verifier::Verifier for Handle {
    fn sync(&self, height: u64) -> Result<(), Error> {
        let (sender, receiver) = channel::bounded(1);
        self.command_sender
            .send(Command::Synchronize(height, sender))
            .map_err(|_| Error::Internal)?;

        receiver.recv().map_err(|_| Error::Internal)?
    }

    fn verify(
        &self,
        consensus_block: LightBlock,
        runtime_header: Header,
        epoch: EpochTime,
    ) -> Result<ConsensusState, Error> {
        let (sender, receiver) = channel::bounded(1);
        self.command_sender
            .send(Command::Verify(
                consensus_block,
                runtime_header,
                epoch,
                sender,
                false,
            ))
            .map_err(|_| Error::Internal)?;

        receiver.recv().map_err(|_| Error::Internal)?
    }

    fn verify_for_query(
        &self,
        consensus_block: LightBlock,
        runtime_header: Header,
        epoch: EpochTime,
    ) -> Result<ConsensusState, Error> {
        let (sender, receiver) = channel::bounded(1);
        self.command_sender
            .send(Command::Verify(
                consensus_block,
                runtime_header,
                epoch,
                sender,
                true,
            ))
            .map_err(|_| Error::Internal)?;

        receiver.recv().map_err(|_| Error::Internal)?
    }

    fn unverified_state(&self, consensus_block: LightBlock) -> Result<ConsensusState, Error> {
        let untrusted_block =
            decode_light_block(consensus_block).map_err(Error::VerificationFailed)?;
        // NOTE: No actual verification is performed.
        let state_root = untrusted_block.get_state_root();
        Ok(ConsensusState::from_protocol(
            self.protocol.clone(),
            state_root,
        ))
    }

    fn latest_state(&self) -> Result<ConsensusState, Error> {
        let (sender, receiver) = channel::bounded(1);
        self.command_sender
            .send(Command::LatestState(sender))
            .map_err(|_| Error::Internal)?;

        receiver.recv().map_err(|_| Error::Internal)?
    }

    fn trust(&self, header: &ComputeResultsHeader) -> Result<(), Error> {
        let (sender, receiver) = channel::bounded(1);
        self.command_sender
            .send(Command::Trust(header.clone(), sender))
            .map_err(|_| Error::Internal)?;

        receiver.recv().map_err(|_| Error::Internal)?
    }
}

struct Io {
    protocol: Arc<Protocol>,
}

impl Io {
    fn new(protocol: &Arc<Protocol>) -> Self {
        Self {
            protocol: protocol.clone(),
        }
    }

    fn fetch_light_block(&self, height: u64) -> Result<LightBlockMeta, components::io::IoError> {
        use components::io::IoError;

        let result = self
            .protocol
            .call_host(
                Context::background(),
                Body::HostFetchConsensusBlockRequest { height },
            )
            .map_err(|err| IoError::rpc(RpcError::server(err.to_string())))?;

        // Extract generic light block from response.
        let block = match result {
            Body::HostFetchConsensusBlockResponse { block } => block,
            _ => return Err(IoError::rpc(RpcError::server("bad response".to_string()))),
        };

        // Decode block as a Tendermint light block.
        let block = decode_light_block(block)
            .map_err(|err| IoError::rpc(RpcError::server(err.to_string())))?;

        Ok(block)
    }
}

impl components::io::Io for Io {
    fn fetch_light_block(
        &self,
        height: components::io::AtHeight,
    ) -> Result<TMLightBlock, components::io::IoError> {
        use components::io::IoError;

        let height = match height {
            components::io::AtHeight::At(height) => height.into(),
            components::io::AtHeight::Highest => HEIGHT_LATEST,
        };

        // Fetch light block at height and height+1.
        let block = Io::fetch_light_block(self, height)?;
        let height: u64 = block
            .signed_header
            .as_ref()
            .ok_or_else(|| IoError::rpc(RpcError::server("missing signed header".to_string())))?
            .header()
            .height
            .into();
        // NOTE: It seems that the requirement to fetch the next validator set is redundant and it
        //       should be handled at a higher layer of the light client.
        let next_block = Io::fetch_light_block(self, height + 1)?;

        Ok(TMLightBlock {
            signed_header: block.signed_header.unwrap(), // Checked above.
            validators: block.validators,
            next_validators: next_block.validators,
            provider: PeerId::new([0; 20]),
        })
    }
}

struct InsecureClock;

impl components::clock::Clock for InsecureClock {
    fn now(&self) -> Time {
        Time::from_unix_timestamp(time::insecure_posix_time(), 0).unwrap()
    }
}

// Voting power calculator which uses Oasis Core's domain separation for verifying signatures.
struct DomSepVotingPowerCalculator;

impl VotingPowerCalculator for DomSepVotingPowerCalculator {
    fn voting_power_in(
        &self,
        signed_header: &SignedHeader,
        validator_set: &ValidatorSet,
        trust_threshold: TrustThreshold,
    ) -> Result<VotingPowerTally, VerificationError> {
        let signatures = &signed_header.commit.signatures;

        let mut tallied_voting_power = 0_u64;
        let mut seen_validators = HashSet::new();

        // Get non-absent votes from the signatures
        let non_absent_votes = signatures.iter().enumerate().flat_map(|(idx, signature)| {
            non_absent_vote(
                signature,
                ValidatorIndex::try_from(idx).unwrap(),
                &signed_header.commit,
            )
            .map(|vote| (signature, vote))
        });

        for (signature, vote) in non_absent_votes {
            // Ensure we only count a validator's power once
            if seen_validators.contains(&vote.validator_address) {
                return Err(VerificationError::duplicate_validator(
                    vote.validator_address,
                ));
            } else {
                seen_validators.insert(vote.validator_address);
            }

            let validator = match validator_set.validator(vote.validator_address) {
                Some(validator) => validator,
                None => continue, // Cannot find matching validator, so we skip the vote
            };

            let signed_vote =
                SignedVote::from_vote(vote.clone(), signed_header.header.chain_id.clone())
                    .ok_or_else(VerificationError::missing_signature)?;

            // Check vote is valid
            let sign_bytes = signed_vote.sign_bytes();
            // Use Oasis Core domain separation scheme.
            let sign_bytes = Hash::digest_bytes_list(&[TENDERMINT_CONTEXT, &sign_bytes]);
            let power = validator.power();
            validator
                .verify_signature(sign_bytes.as_ref(), signed_vote.signature())
                .map_err(|_| {
                    VerificationError::invalid_signature(
                        signed_vote.signature().as_bytes().to_vec(),
                        Box::new(validator),
                        sign_bytes.as_ref().into(),
                    )
                })?;

            // If the vote is neither absent nor nil, tally its power
            if signature.is_commit() {
                tallied_voting_power += power;
            } else {
                // It's OK. We include stray signatures (~votes for nil)
                // to measure validator availability.
            }

            // TODO: Break out of the loop when we have enough voting power.
            // See https://github.com/informalsystems/tendermint-rs/issues/235
        }

        let voting_power = VotingPowerTally {
            total: self.total_power_of(validator_set),
            tallied: tallied_voting_power,
            trust_threshold,
        };

        Ok(voting_power)
    }
}

// Copied from tendermint-rs as it is not public.
fn non_absent_vote(
    commit_sig: &CommitSig,
    validator_index: ValidatorIndex,
    commit: &Commit,
) -> Option<Vote> {
    let (validator_address, timestamp, signature, block_id) = match commit_sig {
        CommitSig::BlockIdFlagAbsent { .. } => return None,
        CommitSig::BlockIdFlagCommit {
            validator_address,
            timestamp,
            signature,
        } => (
            *validator_address,
            *timestamp,
            signature,
            Some(commit.block_id),
        ),
        CommitSig::BlockIdFlagNil {
            validator_address,
            timestamp,
            signature,
        } => (*validator_address, *timestamp, signature, None),
    };

    Some(Vote {
        vote_type: tendermint::vote::Type::Precommit,
        height: commit.height,
        round: commit.round,
        block_id,
        timestamp: Some(timestamp),
        validator_address,
        validator_index,
        signature: signature.clone(),
    })
}
