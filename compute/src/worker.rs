use std::borrow::Borrow;
use std::fmt::Write;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

use grpcio;
use protobuf;
use protobuf::Message;
use thread_local::ThreadLocal;

use ekiden_consensus_api::{self, ConsensusClient};
use ekiden_consensus_base::Block;
use ekiden_core::bytes::H256;
use ekiden_core::contract::batch::{CallBatch, OutputBatch};
use ekiden_core::enclave::api::IdentityProof;
use ekiden_core::enclave::quote;
use ekiden_core::error::{Error, Result};
use ekiden_core::futures::sync::oneshot;
use ekiden_core::rpc::api;
use ekiden_core::rpc::client::ClientEndpoint;
use ekiden_untrusted::{Enclave, EnclaveContract, EnclaveDb, EnclaveIdentity, EnclaveRpc};
use ekiden_untrusted::rpc::router::RpcRouter;

use super::consensus::ConsensusFrontend;
use super::handlers;
use super::ias::IAS;
use super::instrumentation;

/// Result bytes.
pub type BytesResult = Result<Vec<u8>>;
/// Result bytes sender part of the channel.
pub type BytesSender = oneshot::Sender<BytesResult>;

/// Computed batch.
#[derive(Debug)]
pub struct ComputedBatch {
    /// Block this batch was computed against.
    pub block: Block,
    /// Batch of contract calls.
    pub calls: CallBatch,
    /// Batch of contract outputs.
    pub outputs: OutputBatch,
    /// New state root hash.
    pub new_state_root: H256,
}

/// Command sent to the worker thread.
enum Command {
    /// RPC call from a client.
    RpcCall(Vec<u8>, BytesSender, Arc<ConsensusFrontend>),
    /// Contract call batch process request.
    ContractCallBatch(CallBatch, Block, oneshot::Sender<Result<ComputedBatch>>),
}

// TODO: Remove once we start using the new storage backend.
struct CachedStateInitialized {
    encrypted_state: Vec<u8>,
    height: u64,
}

struct WorkerInner {
    /// Consensus client.
    // TODO: Remove once we start using the new storage backend.
    consensus: Option<ConsensusClient>,
    /// Contract running in an enclave.
    contract: Enclave,
    /// Enclave identity proof.
    #[allow(dead_code)]
    identity_proof: IdentityProof,
    /// Cached state reconstituted from checkpoint and diffs. None if
    /// cache or state is uninitialized.
    // TODO: Remove once we start using the new storage backend.
    cached_state: Option<CachedStateInitialized>,
    /// Instrumentation objects.
    ins: instrumentation::WorkerMetrics,
}

impl WorkerInner {
    fn new(config: WorkerConfiguration, ias: Arc<IAS>) -> Self {
        let (contract, identity_proof) =
            Self::create_contract(&config.contract_filename, ias, config.saved_identity_path);

        // Construct consensus client.
        // TODO: Remove once we start using the new storage backend.
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
            // TODO: Remove once we start using the new storage backend.
            cached_state: None,
            ins: instrumentation::WorkerMetrics::new(),
            // TODO: Remove once we start using the new storage backend.
            consensus,
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

        info!("Loaded contract with MRENCLAVE: {}", mr_enclave);

        (contract, identity_proof)
    }

    // TODO: Remove once we start using the new storage backend.
    #[cfg(not(feature = "no_cache"))]
    fn get_cached_state_height(&self) -> Option<u64> {
        match self.cached_state.as_ref() {
            Some(csi) => Some(csi.height),
            None => None,
        }
    }

    // TODO: Remove once we start using the new storage backend.
    fn set_cached_state(&mut self, checkpoint: &ekiden_consensus_api::Checkpoint) -> Result<()> {
        self.cached_state = Some(CachedStateInitialized {
            encrypted_state: checkpoint.get_payload().to_vec(),
            height: checkpoint.get_height(),
        });
        Ok(())
    }

    // TODO: Remove once we start using the new storage backend.
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
        // TODO: Remove once we start using the new storage backend.
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

        // TODO: Remove once we start using the new storage backend.
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

        // TODO: Remove once we start using the new storage backend.
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
    fn handle_contract_batch(
        &mut self,
        calls: CallBatch,
        block: Block,
        sender: oneshot::Sender<Result<ComputedBatch>>,
    ) {
        // TODO: Use block to get the state root hash for storage.
        let outputs = self.call_contract_batch_fallible(&calls);

        match outputs {
            Ok(outputs) => {
                // No errors, hand over the batch to consensus.
                // TODO: Use actual state root hash.
                let new_state_root = H256::zero();
                sender
                    .send(Ok(ComputedBatch {
                        block,
                        calls,
                        outputs,
                        new_state_root,
                    }))
                    .unwrap();
            }
            Err(error) => {
                // Batch-wide error has occurred.
                error!("Batch-wide error: {:?}", error);
                sender.send(Err(error)).unwrap();
            }
        }
    }

    /// Check if the most recent RPC call produced any contract calls and queue them
    /// in the current call batch.
    fn check_and_append_contract_batch(&self, consensus_frontend: Arc<ConsensusFrontend>) {
        // Check if the most recent RPC call produced any contract calls.
        match self.contract.contract_take_batch() {
            Ok(batch) => {
                // We got a batch of calls, send it to consensus frontend for batching.
                if !batch.is_empty() {
                    consensus_frontend.append_batch(batch);
                }
            }
            Err(error) => {
                error!(
                    "Failed to take contract batch from contract: {}",
                    error.message
                );
            }
        }
    }

    /// Process requests from a receiver until the channel closes.
    fn work(&mut self, command_receiver: Receiver<Command>) {
        // Block for the next call.
        while let Ok(command) = command_receiver.recv() {
            match command {
                Command::RpcCall(request, sender, consensus_frontend) => {
                    // Process (stateless) RPC call.
                    let result = self.handle_rpc_call(request);
                    sender.send(result).unwrap();

                    // Check if RPC call produced a batch of requests.
                    self.check_and_append_contract_batch(consensus_frontend);
                }
                Command::ContractCallBatch(calls, block, sender) => {
                    // Process batch of contract calls.
                    self.handle_contract_batch(calls, block, sender);
                }
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
    // TODO: Remove once we start using the new storage backend.
    pub consensus_host: String,
    /// Consensus port.
    // TODO: Remove once we start using the new storage backend.
    pub consensus_port: u16,
    /// Optional saved identity path.
    pub saved_identity_path: Option<PathBuf>,
    /// Key manager configuration.
    pub key_manager: Option<KeyManagerConfiguration>,
}

/// Worker which executes contracts in secure enclaves.
pub struct Worker {
    /// Channel for submitting commands to the worker.
    command_sender: Mutex<Sender<Command>>,
    /// Thread-local clone of the command sender which is required to avoid locking the
    /// mutex each time we need to send a command.
    tl_command_sender: ThreadLocal<Sender<Command>>,
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

        // Spawn inner worker in a separate thread.
        let (command_sender, command_receiver) = channel();
        thread::spawn(move || {
            WorkerInner::new(config, ias).work(command_receiver);
        });

        Self {
            command_sender: Mutex::new(command_sender),
            tl_command_sender: ThreadLocal::new(),
        }
    }

    /// Get new clone of command sender for communicating with the worker.
    fn get_command_sender(&self) -> &Sender<Command> {
        self.tl_command_sender.get_or(|| {
            let command_sender = self.command_sender.lock().unwrap();
            Box::new(command_sender.clone())
        })
    }

    /// Queue an RPC call with the worker.
    ///
    /// Returns a receiver that will be used to deliver the response.
    pub fn rpc_call(
        &self,
        request: Vec<u8>,
        consensus_frontend: Arc<ConsensusFrontend>,
    ) -> oneshot::Receiver<BytesResult> {
        let (response_sender, response_receiver) = oneshot::channel();
        self.get_command_sender()
            .send(Command::RpcCall(
                request,
                response_sender,
                consensus_frontend,
            ))
            .unwrap();

        response_receiver
    }

    pub fn contract_call_batch(
        &self,
        calls: CallBatch,
        block: Block,
    ) -> oneshot::Receiver<Result<ComputedBatch>> {
        let (response_sender, response_receiver) = oneshot::channel();
        self.get_command_sender()
            .send(Command::ContractCallBatch(calls, block, response_sender))
            .unwrap();

        response_receiver
    }
}
