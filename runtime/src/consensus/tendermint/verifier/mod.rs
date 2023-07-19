//! Tendermint consensus layer verification logic.
use std::{convert::TryInto, str::FromStr, sync::Arc, time::Duration};

use anyhow::anyhow;
use crossbeam::channel;
use rand::{rngs::OsRng, Rng};
use sha2::{Digest, Sha256};
use slog::{debug, error, info};
use tendermint::merkle::HASH_SIZE;
use tendermint_light_client::{
    builder::LightClientBuilder,
    components::{self, io::AtHeight, verifier::PredicateVerifier},
    light_client,
    operations::{ProdCommitValidator, ProvidedVotingPowerCalculator},
    store::LightStore,
    supervisor::Instance,
    types::{
        Hash as TMHash, LightBlock as TMLightBlock, PeerId, Status, Time, TrustThreshold,
        TrustedBlockState,
    },
    verifier::{predicates::ProdPredicates, Verdict, Verifier as TMVerifier},
};

use crate::{
    common::{logger::get_logger, namespace::Namespace, process, time, version::Version},
    consensus::{
        beacon::EpochTime,
        registry::METHOD_PROVE_FRESHNESS,
        roothash::Header,
        state::ConsensusState,
        tendermint::{
            chain_id, decode_light_block, merkle, state_root_from_header,
            verifier::{
                clock::InsecureClock,
                io::Io,
                store::LruStore,
                types::{Command, Nonce, NONCE_SIZE},
            },
            LightBlockMeta,
        },
        transaction::{Proof, SignedTransaction, Transaction},
        verifier::{self, verify_state_freshness, Error, TrustRoot},
        BlockMetadata, Event, LightBlock, HEIGHT_LATEST, METHOD_META,
    },
    future::block_on,
    host::Host,
    protocol::Protocol,
    storage::mkvs::{Root, RootType},
    types::{Body, EventKind, HostFetchConsensusEventsRequest, HostFetchConsensusEventsResponse},
};

use self::{
    cache::Cache,
    handle::Handle,
    store::{TrustedState, TrustedStateStore},
};

// Modules.
mod cache;
mod clock;
mod handle;
mod io;
mod noop;
mod predicates;
mod signature;
mod store;
mod types;

// Re-exports.
pub use noop::NopVerifier;

/// Maximum number of times to retry initialization.
const MAX_INITIALIZATION_RETRIES: usize = 3;

/// Trusted state save interval (in consensus blocks).
const TRUSTED_STATE_SAVE_INTERVAL: u64 = 128;

/// Tendermint consensus layer verifier.
pub struct Verifier {
    logger: slog::Logger,
    protocol: Arc<Protocol>,
    tokio_runtime: tokio::runtime::Handle,
    runtime_version: Version,
    runtime_id: Namespace,
    chain_context: String,
    trust_root: TrustRoot,
    command_sender: channel::Sender<Command>,
    command_receiver: channel::Receiver<Command>,
    trusted_state_store: TrustedStateStore,
}

impl Verifier {
    /// Create a new Tendermint consensus layer verifier.
    pub fn new(
        protocol: Arc<Protocol>,
        tokio_runtime: tokio::runtime::Handle,
        trust_root: TrustRoot,
        runtime_id: Namespace,
        chain_context: String,
    ) -> Self {
        let logger = get_logger("consensus/cometbft/verifier");
        let (command_sender, command_receiver) = channel::unbounded();
        let runtime_version = protocol.get_config().version;
        let trusted_state_store =
            TrustedStateStore::new(runtime_id, chain_context.clone(), protocol.clone());

        assert_eq!(
            trust_root.runtime_id, runtime_id,
            "trust root must have the same runtime id"
        );

        Self {
            logger,
            protocol,
            tokio_runtime,
            runtime_version,
            runtime_id,
            chain_context,
            trust_root,
            command_sender,
            command_receiver,
            trusted_state_store,
        }
    }

    /// Return a handle to interact with the verifier.
    pub fn handle(&self) -> impl verifier::Verifier {
        Handle {
            protocol: self.protocol.clone(),
            command_sender: self.command_sender.clone(),
        }
    }

    fn verify_to_target(
        &self,
        height: u64,
        cache: &mut Cache,
        instance: &mut Instance,
    ) -> Result<TMLightBlock, Error> {
        let verified_block = match height {
            HEIGHT_LATEST => instance.light_client.verify_to_highest(&mut instance.state),
            _ => instance
                .light_client
                .verify_to_target(height.try_into().unwrap(), &mut instance.state),
        }
        .map_err(|err| Error::VerificationFailed(err.into()))?;

        // Clear verification trace as it could otherwise lead to infinite memory growth.
        instance.state.verification_trace.clear();

        cache.update_verified_block(&verified_block);
        self.update_insecure_posix_time(&verified_block);

        Ok(verified_block)
    }

    fn sync(&self, cache: &mut Cache, instance: &mut Instance, height: u64) -> Result<(), Error> {
        if height < cache.last_verified_height || height < cache.latest_known_height().unwrap_or(0)
        {
            // Ignore requests for earlier heights.
            return Ok(());
        }
        self.verify_to_target(height, cache, instance)?;
        Ok(())
    }

    fn latest_consensus_state(
        &self,
        cache: &mut Cache,
        instance: &mut Instance,
    ) -> Result<ConsensusState, Error> {
        let height = self.latest_consensus_height(cache)?;
        self.consensus_state_at(cache, instance, height)
    }

    fn latest_consensus_height(&self, cache: &Cache) -> Result<u64, Error> {
        let height = cache.latest_known_height().ok_or(Error::Internal)?;
        Ok(height)
    }

    fn consensus_state_at(
        &self,
        cache: &mut Cache,
        instance: &mut Instance,
        height: u64,
    ) -> Result<ConsensusState, Error> {
        // Obtain an authoritative state root, either from the current block if it is already
        // finalized or from the metadata transaction of the previous block.
        let state_root = match self.verify_to_target(height, cache, instance) {
            Ok(verified_block) => state_root_from_header(&verified_block.signed_header),
            Err(_) => self.state_root_from_metadata(cache, instance, height - 1)?,
        };

        Ok(ConsensusState::from_protocol(
            self.protocol.clone(),
            state_root.version + 1,
            state_root,
        ))
    }

    fn verify_consensus_block(
        &self,
        cache: &mut Cache,
        instance: &mut Instance,
        consensus_block: LightBlock,
    ) -> Result<LightBlockMeta, Error> {
        // Decode passed block as a Tendermint block.
        let lb_height = consensus_block.height;
        let untrusted_block =
            decode_light_block(consensus_block).map_err(Error::VerificationFailed)?;
        let untrusted_header = untrusted_block
            .signed_header
            .as_ref()
            .ok_or_else(|| Error::VerificationFailed(anyhow!("missing signed header")))?;

        // Verify up to the block at current height.
        // Only does forward verification and fails if height is lower than the last trust height.
        let height = untrusted_header.header().height.value();
        if height != lb_height {
            return Err(Error::VerificationFailed(anyhow!(
                "inconsistent light block/header height"
            )));
        }
        let verified_block = self.verify_to_target(height, cache, instance)?;

        // Validate passed consensus block.
        if untrusted_header.header() != verified_block.signed_header.header() {
            return Err(Error::VerificationFailed(anyhow!("header mismatch")));
        }

        Ok(untrusted_block)
    }

    /// Verify state freshness using RAK and nonces.
    fn verify_freshness_with_rak(
        &self,
        state: &ConsensusState,
        cache: &Cache,
    ) -> Result<(), Error> {
        let identity = if let Some(identity) = self.protocol.get_identity() {
            identity
        } else {
            return Ok(());
        };

        verify_state_freshness(
            state,
            identity,
            &self.runtime_id,
            &self.runtime_version,
            &cache.host_node_id,
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
    fn verify_freshness_with_proof(
        &self,
        instance: &mut Instance,
        cache: &mut Cache,
    ) -> Result<(), Error> {
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
        let stwp = io.fetch_freshness_proof(&nonce).map_err(|err| {
            Error::FreshnessVerificationFailed(anyhow!("failed to fetch freshness proof: {}", err))
        })?;

        // Verify the transaction and the proof.
        let tx = self.verify_transaction(cache, instance, &stwp.signed_tx, &stwp.proof)?;

        // Verify the method name and the nonce.
        if tx.method != METHOD_PROVE_FRESHNESS {
            return Err(Error::FreshnessVerificationFailed(anyhow!(
                "invalid method name"
            )));
        }

        let tx_nonce: Nonce = cbor::from_value(tx.body).map_err(|err| {
            Error::FreshnessVerificationFailed(anyhow!("failed to decode nonce: {}", err))
        })?;
        match nonce.cmp(&tx_nonce) {
            std::cmp::Ordering::Equal => (),
            _ => return Err(Error::FreshnessVerificationFailed(anyhow!("invalid nonce"))),
        }

        info!(self.logger, "State freshness successfully verified");

        Ok(())
    }

    fn verify_transaction(
        &self,
        cache: &mut Cache,
        instance: &mut Instance,
        signed_tx: &SignedTransaction,
        proof: &Proof,
    ) -> Result<Transaction, Error> {
        // Verify the signature.
        if !signed_tx.verify(&self.chain_context) {
            return Err(Error::TransactionVerificationFailed(anyhow!(
                "failed to verify the signature"
            )));
        }

        // Fetch the root hash of a block in which the transaction was published.
        let verified_block = self
            .verify_to_target(proof.height, cache, instance)
            .map_err(|err| {
                Error::TransactionVerificationFailed(anyhow!("failed to fetch the block: {}", err))
            })?;

        let header = verified_block.signed_header.header;
        if header.height.value() != proof.height {
            return Err(Error::TransactionVerificationFailed(anyhow!(
                "invalid block"
            )));
        }

        let root_hash = header
            .data_hash
            .ok_or_else(|| Error::TransactionVerificationFailed(anyhow!("root hash not found")))?;
        let root_hash = match root_hash {
            TMHash::Sha256(hash) => hash,
            TMHash::None => {
                return Err(Error::TransactionVerificationFailed(anyhow!(
                    "root hash not found"
                )));
            }
        };

        // Compute hash of the transaction.
        let digest = Sha256::digest(&cbor::to_vec(signed_tx.clone()));
        let mut tx_hash = [0u8; HASH_SIZE];
        tx_hash.copy_from_slice(&digest);

        // Decode raw proof as a CometBFT Merkle proof of inclusion.
        let merkle_proof: merkle::Proof = cbor::from_slice(&proof.raw_proof).map_err(|err| {
            Error::TransactionVerificationFailed(anyhow!("failed to decode Merkle proof: {}", err))
        })?;

        merkle_proof.verify(root_hash, tx_hash).map_err(|err| {
            Error::TransactionVerificationFailed(anyhow!("failed to verify Merkle proof: {}", err))
        })?;

        // Decode transaction.
        let tx: Transaction = cbor::from_slice(signed_tx.blob.as_slice()).map_err(|err| {
            Error::TransactionVerificationFailed(anyhow!("failed to decode transaction: {}", err))
        })?;

        Ok(tx)
    }

    /// Fetch state root from block metadata transaction.
    fn state_root_from_metadata(
        &self,
        cache: &mut Cache,
        instance: &mut Instance,
        height: u64,
    ) -> Result<Root, Error> {
        debug!(
            self.logger,
            "Fetching state root from block metadata transaction"
        );

        // Ask the host for block metadata transaction.
        let io = Io::new(&self.protocol);
        let stwp = io.fetch_block_metadata(height).map_err(|err| {
            Error::StateRoot(anyhow!(
                "failed to fetch block metadata transaction: {}",
                err
            ))
        })?;

        // Verify the transaction and the proof.
        let tx = self.verify_transaction(cache, instance, &stwp.signed_tx, &stwp.proof)?;

        if tx.method != METHOD_META {
            return Err(Error::StateRoot(anyhow!("invalid method name")));
        }

        let meta: BlockMetadata = cbor::from_value(tx.body).map_err(|err| {
            Error::StateRoot(anyhow!(
                "failed to decode block metadata transaction: {}",
                err
            ))
        })?;

        Ok(Root {
            namespace: Namespace::default(),
            version: height,
            root_type: RootType::State,
            hash: meta.state_root,
        })
    }

    fn verify(
        &self,
        cache: &mut Cache,
        instance: &mut Instance,
        consensus_block: LightBlock,
        runtime_header: Header,
        epoch: EpochTime,
    ) -> Result<ConsensusState, Error> {
        // Perform basic verifications.
        predicates::verify_namespace(self.runtime_id, &runtime_header)?;
        predicates::verify_round_advance(cache, &runtime_header, &consensus_block, epoch)?;
        predicates::verify_consensus_advance(cache, &consensus_block)?;

        // Verify the consensus layer block.
        let height = consensus_block.height;
        let consensus_block = self.verify_consensus_block(cache, instance, consensus_block)?;

        // Perform basic verifications.
        predicates::verify_time(&runtime_header, &consensus_block)?;

        // Obtain an authoritative state root.
        let state = self.consensus_state_at(cache, instance, height)?;

        // Check if we have already verified this runtime header to avoid re-verification.
        if let Some((state_root, state_epoch)) =
            cache.verified_state_roots.get(&runtime_header.round)
        {
            if state_root == &runtime_header.state_root
                && state_epoch == &epoch
                && epoch == cache.last_verified_epoch
            {
                // Header and epoch matches, no need to perform re-verification.

                // Cache last verified fields.
                cache.last_verified_height = height;
                cache.last_verified_round = runtime_header.round;

                return Ok(state);
            }

            // Force full verification in case of cache mismatch.
        }

        // Obtain an authoritative state root for full verification.
        // Note that we cannot return the state at height+1 as the block might not have been
        // finalized yet, and we won't be able to query block results such as events.
        let next_state = self.consensus_state_at(cache, instance, height + 1)?;

        // Perform full verification.
        predicates::verify_state_root(&next_state, &runtime_header)?;
        predicates::verify_epoch(&next_state, epoch)?;

        // Verify our own RAK is published in registry once per epoch.
        // This ensures consensus state is recent enough.
        if cache.last_verified_epoch != epoch {
            self.verify_freshness_with_rak(&next_state, cache)?;
        }

        // Cache verified state root and epoch.
        cache
            .verified_state_roots
            .put(runtime_header.round, (runtime_header.state_root, epoch));

        // Cache last verified fields.
        cache.last_verified_height = height;
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
        // Perform basic verifications.
        predicates::verify_namespace(self.runtime_id, &runtime_header)?;

        // Verify the consensus layer block.
        let height = consensus_block.height;
        let consensus_block = self.verify_consensus_block(cache, instance, consensus_block)?;

        // Perform basic verifications.
        predicates::verify_time(&runtime_header, &consensus_block)?;

        // Obtain an authoritative state root.
        let state = self.consensus_state_at(cache, instance, height)?;

        // Check if we have already verified this runtime header to avoid re-verification.
        if let Some((state_root, state_epoch)) =
            cache.verified_state_roots.get(&runtime_header.round)
        {
            if state_root == &runtime_header.state_root && state_epoch == &epoch {
                // Header and epoch matches, no need to perform re-verification.
                return Ok(state);
            }

            // Force full verification in case of cache mismatch.
        }

        // Obtain an authoritative state root for full verification.
        // Note that we cannot return the state at height+1 as the block might not have been
        // finalized yet, and we won't be able to query block results such as events.
        let next_state = self.consensus_state_at(cache, instance, height + 1)?;

        // Perform full verification.
        predicates::verify_state_root(&next_state, &runtime_header)?;
        predicates::verify_epoch(&next_state, epoch)?;

        // Cache verified state root and epoch.
        cache
            .verified_state_roots
            .put(runtime_header.round, (runtime_header.state_root, epoch));

        Ok(state)
    }

    fn events_at(&self, height: u64, kind: EventKind) -> Result<Vec<Event>, Error> {
        let result = self
            .protocol
            .call_host(Body::HostFetchConsensusEventsRequest(
                HostFetchConsensusEventsRequest { height, kind },
            ))
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

    /// Start the verifier in a separate thread.
    pub fn start(self) {
        std::thread::spawn(move || {
            let _guard = self.tokio_runtime.enter(); // Ensure Tokio runtime is available.

            let logger = get_logger("consensus/cometbft/verifier");
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
                            process::abort();
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
                        process::abort();
                    }
                }

                // Retry to initialize the verifier.
                std::thread::sleep(Duration::from_secs(1));
            }

            error!(logger, "Failed to start consensus verifier, aborting");
            process::abort();
        });
    }

    fn run(&self) -> Result<(), Error> {
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
            ProvidedVotingPowerCalculator::<signature::DomSepVerifier>::default(),
            ProdCommitValidator::default(),
        ));
        let io = Box::new(Io::new(&self.protocol));

        // Build a light client using the embedded trust root or trust root
        // stored in the local store.
        info!(self.logger, "Loading trusted state");
        let trusted_state: TrustedState = self
            .trusted_state_store
            .load(self.runtime_version, &self.trust_root)?;

        // Verify if we can trust light blocks from a new chain if the consensus
        // chain context changes.
        info!(self.logger, "Checking chain context change");
        let trusted_state = self.handle_chain_context_change(
            trusted_state,
            verifier.as_ref(),
            clock.as_ref(),
            io.as_ref(),
        )?;

        // Insert all of the trusted blocks into the light store as trusted.
        let mut store = Box::new(LruStore::new(
            512,
            trusted_state.trust_root.height.try_into().unwrap(),
        ));
        for lb in trusted_state.trusted_blocks {
            store.insert(lb.into(), Status::Trusted);
        }
        let trust_root = trusted_state.trust_root;

        let builder = LightClientBuilder::custom(
            peer_id,
            options,
            store,
            io,
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

        let host_node_id =
            block_on(self.protocol.identity()).expect("host should provide a node identity");

        let mut cache = Cache::new(host_node_id);

        // Sync the verifier up to the latest block to make sure we are up to date before
        // processing any requests.
        let verified_block = self.verify_to_target(HEIGHT_LATEST, &mut cache, &mut instance)?;

        self.trusted_state_store
            .save(self.runtime_version, &instance.state.light_store);

        let mut last_saved_verified_block_height =
            verified_block.signed_header.header.height.value();

        info!(self.logger, "Consensus verifier synced";
            "latest_height" => cache.latest_known_height(),
        );

        // Verify state freshness with freshness proof. This step is required only for clients
        // as executors and key managers verify freshness regularly using node registration
        // (RAK with random nonces).
        if self.protocol.get_config().freshness_proofs {
            self.verify_freshness_with_proof(&mut instance, &mut cache)?;
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
            if let Some(last_verified_block) = cache.last_verified_block.as_ref() {
                let last_height = last_verified_block.signed_header.header.height.into();
                if last_height - last_saved_verified_block_height > TRUSTED_STATE_SAVE_INTERVAL {
                    self.trusted_state_store
                        .save(self.runtime_version, &instance.state.light_store);
                    last_saved_verified_block_height = last_height;
                }
            }
        }
    }

    fn handle_chain_context_change(
        &self,
        mut trusted_state: TrustedState,
        verifier: &impl TMVerifier,
        clock: &impl components::clock::Clock,
        io: &Io,
    ) -> Result<TrustedState, Error> {
        let host_info = self.protocol.get_host_info();

        // Nothing to handle.
        if trusted_state.trust_root.chain_context == host_info.consensus_chain_context {
            info!(self.logger, "Consensus chain context hasn't changed");
            return Ok(trusted_state);
        }
        info!(self.logger, "Consensus chain context has changed");

        // Chain context transition cannot be done directly from the embedded
        // trust root as we don't have access to the matching trusted light
        // block which validator set we need to verify blocks from the new chain.
        let trusted_block: TMLightBlock = trusted_state
            .trusted_blocks
            .pop()
            .ok_or_else(|| {
                Error::ChainContextTransitionFailed(anyhow!(
                    "cannot transition from embedded trust root"
                ))
            })?
            .into();

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
        let header = trusted_block.signed_header.header;
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
            next_validators: &trusted_block.validators,
            next_validators_hash: header.validators_hash,
            // We need to use the target chain ID as we know it has changed.
            chain_id: &chain_id(&host_info.consensus_chain_context),
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
                    "log_event" => "consensus/cometbft/verifier/chain_context/no_trust",
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
                    "log_event" => "consensus/cometbft/verifier/chain_context/failed",
                    "error" => ?e,
                );
                return Err(Error::ChainContextTransitionFailed(anyhow!(
                    "invalid genesis block"
                )));
            }
        }

        info!(self.logger, "Consensus chain context transition done");

        let header = &untrusted_block.signed_header.header;
        let trust_root = TrustRoot {
            height: header.height.into(),
            hash: header.hash().to_string(),
            runtime_id: self.runtime_id,
            chain_context: host_info.consensus_chain_context,
        };

        Ok(TrustedState {
            trust_root,
            trusted_blocks: vec![untrusted_block.into()],
        })
    }
}
