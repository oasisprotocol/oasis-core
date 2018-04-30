use std;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt::Write;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use grpcio;
use lru_cache::LruCache;
use protobuf;
use protobuf::Message;

use ekiden_consensus_api::{self, ConsensusClient};
use ekiden_core::bytes::H256;
use ekiden_core::contract::batch::{CallBatch, OutputBatch};
use ekiden_core::enclave::api::IdentityProof;
use ekiden_core::enclave::quote;
use ekiden_core::error::{Error, Result};
use ekiden_core::futures::sync::oneshot;
use ekiden_core::hash::EncodedHash;
use ekiden_core::rpc::api;
use ekiden_core::rpc::client::ClientEndpoint;
use ekiden_untrusted::{Enclave, EnclaveContract, EnclaveDb, EnclaveIdentity, EnclaveRpc};
use ekiden_untrusted::rpc::router::RpcRouter;

use super::handlers;
use super::ias::IAS;
use super::instrumentation;

/// Result bytes.
pub type BytesResult = Result<Vec<u8>>;
/// Result bytes sender part of the channel.
pub type BytesSender = oneshot::Sender<BytesResult>;

/// Call batch that is being constructed.
#[derive(Debug)]
pub struct PendingBatch {
    /// Instant when first item was queued in the batch.
    start: Instant,
    /// Call batch.
    batch: CallBatch,
}

/// Command sent to the worker thread.
#[derive(Debug)]
pub enum Command {
    /// RPC call from a client.
    RpcCall(Vec<u8>, BytesSender),
    /// Contract call batch process request.
    ContractCallBatch(CallBatch),
    /// Contract call subscription request.
    SubscribeCall(H256, BytesSender),
    /// Ping worker.
    Ping,
}

struct CachedStateInitialized {
    encrypted_state: Vec<u8>,
    height: u64,
}

struct WorkerInner {
    /// Consensus client.
    consensus: Option<ConsensusClient>,
    /// Contract running in an enclave.
    contract: Enclave,
    /// Enclave identity proof.
    #[allow(dead_code)]
    identity_proof: IdentityProof,
    /// Cached state reconstituted from checkpoint and diffs. None if
    /// cache or state is uninitialized.
    cached_state: Option<CachedStateInitialized>,
    /// Instrumentation objects.
    ins: instrumentation::WorkerMetrics,
    /// Maximum batch size.
    max_batch_size: usize,
    /// Maximum batch timeout.
    max_batch_timeout: Duration,
    /// Current batch.
    current_batch: Option<PendingBatch>,
    /// Batch call subscriptions.
    subscriptions_call: HashMap<H256, Vec<BytesSender>>,
    /// Processed calls without subscriptions. We keep a LRU cache of such call results
    /// around so that subscription requests can arrive even after the batch has been
    /// processed.
    missed_calls: LruCache<H256, BytesResult>,
}

impl WorkerInner {
    fn new(config: WorkerConfiguration, ias: Arc<IAS>) -> Self {
        let (contract, identity_proof) =
            Self::create_contract(&config.contract_filename, ias, config.saved_identity_path);

        // Construct consensus client.
        let consensus = match config.consensus_host.as_ref() {
            "none" => None,
            consensus_host => {
                let env = Arc::new(grpcio::EnvBuilder::new().build());
                let channel = grpcio::ChannelBuilder::new(env)
                    .connect(&format!("{}:{}", consensus_host, config.consensus_port));
                Some(ConsensusClient::new(channel))
            }
        };

        Self {
            contract,
            identity_proof,
            cached_state: None,
            ins: instrumentation::WorkerMetrics::new(),
            max_batch_size: config.max_batch_size,
            max_batch_timeout: Duration::from_millis(config.max_batch_timeout),
            consensus: consensus,
            current_batch: None,
            subscriptions_call: HashMap::new(),
            missed_calls: LruCache::new(config.max_batch_size * 2),
        }
    }

    /// Create an instance of the contract.
    fn create_contract(
        contract_filename: &str,
        ias: Arc<IAS>,
        saved_identity_path: Option<PathBuf>,
    ) -> (Enclave, IdentityProof) {
        // TODO: Handle contract initialization errors.
        let contract = Enclave::new(contract_filename).unwrap();

        // Initialize contract.
        let identity_proof = contract
            .identity_init(
                ias.deref(),
                saved_identity_path.as_ref().map(|p| p.borrow()),
            )
            .expect("EnclaveIdentity::identity_init");

        // Show contract MRENCLAVE in hex format.
        let iai = quote::verify(&identity_proof).expect("Enclave identity proof invalid");
        let mut mr_enclave = String::new();
        for &byte in &iai.mr_enclave[..] {
            write!(&mut mr_enclave, "{:02x}", byte).unwrap();
        }

        println!("Loaded contract with MRENCLAVE: {}", mr_enclave);

        (contract, identity_proof)
    }

    #[cfg(not(feature = "no_cache"))]
    fn get_cached_state_height(&self) -> Option<u64> {
        match self.cached_state.as_ref() {
            Some(csi) => Some(csi.height),
            None => None,
        }
    }

    fn set_cached_state(&mut self, checkpoint: &ekiden_consensus_api::Checkpoint) -> Result<()> {
        self.cached_state = Some(CachedStateInitialized {
            encrypted_state: checkpoint.get_payload().to_vec(),
            height: checkpoint.get_height(),
        });
        Ok(())
    }

    fn advance_cached_state(&mut self, diffs: &[Vec<u8>]) -> Result<Vec<u8>> {
        #[cfg(feature = "no_diffs")]
        assert!(
            diffs.is_empty(),
            "attempted to apply diffs in a no_diffs build"
        );

        let csi = self.cached_state.as_mut().ok_or(Error::new(
            "advance_cached_state called with uninitialized cached state",
        ))?;

        for diff in diffs {
            csi.encrypted_state = self.contract.db_state_apply(&csi.encrypted_state, &diff)?;
            csi.height += 1;
        }

        Ok(csi.encrypted_state.clone())
    }

    fn call_contract_batch_fallible(&mut self, batch: &CallBatch) -> Result<OutputBatch> {
        // Get state updates from consensus
        let encrypted_state_opt = if self.consensus.is_some() {
            let _consensus_get_timer = self.ins.consensus_get_time.start_timer();

            #[cfg(not(feature = "no_cache"))]
            let cached_state_height = self.get_cached_state_height();
            #[cfg(feature = "no_cache")]
            let cached_state_height = None;

            match cached_state_height {
                Some(height) => {
                    let consensus_response = self.consensus.as_ref().unwrap().get_diffs(&{
                        let mut consensus_request = ekiden_consensus_api::GetDiffsRequest::new();
                        consensus_request.set_since_height(height);
                        consensus_request
                    })?;
                    if consensus_response.has_checkpoint() {
                        self.set_cached_state(consensus_response.get_checkpoint())?;
                    }
                    Some(self.advance_cached_state(consensus_response.get_diffs())?)
                }
                None => {
                    if let Ok(consensus_response) = self.consensus
                        .as_ref()
                        .unwrap()
                        .get(&ekiden_consensus_api::GetRequest::new())
                    {
                        self.set_cached_state(consensus_response.get_checkpoint())?;
                        Some(self.advance_cached_state(consensus_response.get_diffs())?)
                    } else {
                        // We should bail if there was an error other
                        // than the state not being initialized. But
                        // don't go fixing this. There's another
                        // resolution planned in #95.
                        None
                    }
                }
            }
        } else {
            None
        };

        #[cfg(not(feature = "no_diffs"))]
        let orig_encrypted_state_opt = encrypted_state_opt.clone();
        #[cfg(feature = "no_diffs")]
        let orig_encrypted_state_opt = None;

        // Add state if it is available.
        if let Some(encrypted_state) = encrypted_state_opt {
            self.contract.db_state_set(&encrypted_state)?;
        }

        let outputs = {
            let _enclave_timer = self.ins.req_time_enclave.start_timer();
            self.contract.contract_call_batch(batch)
        }?;

        // Check if any state was produced. In case no state was produced, this means that
        // no request caused a state update and thus no state update is required.
        let encrypted_state = self.contract.db_state_get()?;
        if self.consensus.is_some() && !encrypted_state.is_empty() {
            let _consensus_set_timer = self.ins.consensus_set_time.start_timer();
            match orig_encrypted_state_opt {
                Some(orig_encrypted_state) => {
                    let diff_res = self.contract
                        .db_state_diff(&orig_encrypted_state, &encrypted_state)?;

                    self.consensus.as_ref().unwrap().add_diff(&{
                        let mut add_diff_req = ekiden_consensus_api::AddDiffRequest::new();
                        add_diff_req.set_payload(diff_res);
                        add_diff_req
                    })?;
                }
                None => {
                    let mut consensus_replace_request = ekiden_consensus_api::ReplaceRequest::new();
                    consensus_replace_request.set_payload(encrypted_state);

                    self.consensus
                        .as_ref()
                        .unwrap()
                        .replace(&consensus_replace_request)?;
                }
            }
        }

        Ok(outputs)
    }

    /// Handle RPC call.
    fn handle_rpc_call(&self, request: Vec<u8>) -> BytesResult {
        // Call contract.
        let mut enclave_request = api::EnclaveRequest::new();
        {
            let client_requests = enclave_request.mut_client_request();
            // TODO: Why doesn't enclave request contain bytes directly?
            let client_request = protobuf::parse_from_bytes(&request)?;
            client_requests.push(client_request);
        }

        let enclave_response = {
            let _enclave_timer = self.ins.req_time_enclave.start_timer();
            self.contract.call(enclave_request)
        }?;

        match enclave_response.get_client_response().first() {
            Some(enclave_response) => Ok(enclave_response.write_to_bytes()?),
            None => Err(Error::new("no response to rpc call")),
        }
    }

    /// Handle contract call batch.
    fn handle_contract_batch(&mut self, batch: CallBatch) {
        let outputs = self.call_contract_batch_fallible(&batch);

        match outputs {
            Ok(mut outputs) => {
                // No errors, send per-call outputs.
                for (output, call) in outputs.drain(..).zip(batch.iter()) {
                    let call_id = call.get_encoded_hash();
                    if let Some(senders) = self.subscriptions_call.remove(&call_id) {
                        for sender in senders {
                            // Explicitly ignore send errors as the receiver may have gone.
                            drop(sender.send(Ok(output.clone())));
                        }
                    }

                    self.missed_calls.insert(call_id, Ok(output));
                }
            }
            Err(error) => {
                // Batch-wide error has occurred.
                eprintln!("batch-wide error: {:?}", error);

                for call in batch.iter() {
                    let call_id = call.get_encoded_hash();
                    if let Some(senders) = self.subscriptions_call.remove(&call_id) {
                        for sender in senders {
                            // Explicitly ignore send errors as the receiver may have gone.
                            drop(sender.send(Err(error.clone())));
                        }
                    }

                    self.missed_calls.insert(call_id, Err(error.clone()));
                }
            }
        }
    }

    /// Check if the most recent RPC call produced any contract calls and queue them
    /// in the current call batch.
    fn queue_contract_batch(&mut self) {
        // Check if the most recent RPC call produced any contract calls.
        let mut batch = self.contract.contract_take_batch().unwrap();
        if batch.is_empty() {
            return;
        }

        if let Some(ref mut current_batch) = self.current_batch {
            // Append to current batch.
            current_batch.batch.append(&mut batch);
        } else {
            // Start new batch.
            self.current_batch = Some(PendingBatch {
                start: Instant::now(),
                batch,
            });
        }
    }

    /// Check if we need to send the current batch for processing.
    ///
    /// The batch is then sent for processing if either:
    /// * Number of calls it contains reaches `max_batch_size`.
    /// * More than `max_batch_timeout` time elapsed since batch was created.
    fn check_and_send_contract_batch(&mut self, command_sender: &Sender<Command>) {
        let should_process = if let Some(ref current_batch) = self.current_batch {
            current_batch.batch.len() >= self.max_batch_size
                || current_batch.start.elapsed() >= self.max_batch_timeout
        } else {
            false
        };

        if should_process {
            // Unwrap is safe as if the batch was none, we should not enter this block.
            let current_batch = self.current_batch.take().unwrap();
            command_sender
                .send(Command::ContractCallBatch(current_batch.batch))
                .unwrap();
        }
    }

    /// Remove any subscribers where the receiver part has been dropped.
    fn clean_subscribers(&mut self) {
        self.subscriptions_call.retain(|_call_id, senders| {
            // Only retain non-canceled senders.
            senders.retain(|sender| !sender.is_canceled());
            // Only retain call ids for which there are subscriptions.
            !senders.is_empty()
        });
    }

    /// Process requests from a receiver until the channel closes.
    fn work(&mut self, command_sender: Sender<Command>, command_receiver: Receiver<Command>) {
        // Ping processing thread every max_batch_timeout.
        let command_sender_clone = command_sender.clone();
        let max_batch_timeout = self.max_batch_timeout;
        std::thread::spawn(move || {
            while command_sender_clone.send(Command::Ping).is_ok() {
                std::thread::sleep(max_batch_timeout);
            }
        });

        // Block for the next call.
        while let Ok(command) = command_receiver.recv() {
            match command {
                Command::RpcCall(request, sender) => {
                    // Process (stateless) RPC call.
                    let result = self.handle_rpc_call(request);
                    sender.send(result).unwrap();

                    // Check if RPC call produced a batch of requests.
                    self.queue_contract_batch();
                }
                Command::ContractCallBatch(batch) => {
                    // Process batch of contract calls.
                    self.handle_contract_batch(batch);
                }
                Command::SubscribeCall(call_id, sender) => {
                    self.subscribe_contract_batch(call_id, sender);
                }
                Command::Ping => {}
            }

            self.check_and_send_contract_batch(&command_sender);
            self.clean_subscribers();
        }
    }

    /// Subscribe to a specific call being processed in a batch.
    fn subscribe_contract_batch(&mut self, call_id: H256, sender: BytesSender) {
        // First check if there are any hits under missed calls. In this case emit
        // the result immediately.
        if let Some(result) = self.missed_calls.get_mut(&call_id) {
            sender.send(result.clone()).unwrap();
            return;
        }

        match self.subscriptions_call.entry(call_id) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().push(sender);
            }
            Entry::Vacant(entry) => {
                entry.insert(vec![sender]);
            }
        }
    }
}

/// Key manager configuration.
#[derive(Clone, Debug)]
pub struct KeyManagerConfiguration {
    /// Compute node host.
    pub host: String,
    /// Compute node port.
    pub port: u16,
}

/// Worker configuration.
#[derive(Clone, Debug)]
pub struct WorkerConfiguration {
    /// Contract binary filename.
    pub contract_filename: String,
    /// Consensus host.
    pub consensus_host: String,
    /// Consensus port.
    pub consensus_port: u16,
    /// Max batch size.
    pub max_batch_size: usize,
    /// Max batch timeout.
    pub max_batch_timeout: u64,
    /// Optional saved identity path.
    pub saved_identity_path: Option<PathBuf>,
    /// Key manager configuration.
    pub key_manager: Option<KeyManagerConfiguration>,
}

/// Worker which executes contracts in secure enclaves.
pub struct Worker {
    /// Channel for submitting commands to the worker.
    command_sender: Mutex<Sender<Command>>,
}

impl Worker {
    /// Create new contract worker.
    pub fn new(
        config: WorkerConfiguration,
        grpc_environment: Arc<grpcio::Environment>,
        ias: Arc<IAS>,
    ) -> Self {
        // Setup enclave RPC routing.
        {
            let mut router = RpcRouter::get_mut();

            // Key manager endpoint.
            if let Some(ref key_manager) = config.key_manager {
                router.add_handler(handlers::ContractForwarder::new(
                    ClientEndpoint::KeyManager,
                    grpc_environment.clone(),
                    key_manager.host.clone(),
                    key_manager.port,
                ));
            }
        }

        // Worker command channel.
        let (command_sender, command_receiver) = channel();
        let command_sender_clone = command_sender.clone();

        // Spawn inner worker in a separate thread.
        thread::spawn(move || {
            WorkerInner::new(config, ias).work(command_sender_clone, command_receiver);
        });

        Self {
            command_sender: Mutex::new(command_sender),
        }
    }

    /// Get new clone of command sender for communicating with the worker.
    pub fn get_command_sender(&self) -> Sender<Command> {
        let command_sender = self.command_sender.lock().unwrap();
        command_sender.clone()
    }
}
