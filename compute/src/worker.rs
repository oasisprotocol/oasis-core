use std::borrow::Borrow;
use std::fmt::Write;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use grpcio;
use protobuf;
use protobuf::Message;
use thread_local::ThreadLocal;

use ekiden_consensus_base::Block;
use ekiden_core::bytes::H256;
use ekiden_core::contract::batch::{CallBatch, OutputBatch};
use ekiden_core::enclave::api::IdentityProof;
use ekiden_core::enclave::quote;
use ekiden_core::error::{Error, Result};
use ekiden_core::futures::sync::oneshot;
use ekiden_core::rpc::api;
use ekiden_core::rpc::client::ClientEndpoint;
use ekiden_storage_base::StorageBackend;
use ekiden_untrusted::rpc::router::RpcRouter;
use ekiden_untrusted::{Enclave, EnclaveContract, EnclaveDb, EnclaveIdentity, EnclaveRpc};

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

struct WorkerInner {
    /// Contract running in an enclave.
    contract: Enclave,
    /// Storage backend.
    storage: Arc<StorageBackend>,
    /// Enclave identity proof.
    #[allow(dead_code)]
    identity_proof: IdentityProof,
    /// Instrumentation objects.
    ins: instrumentation::WorkerMetrics,
}

impl WorkerInner {
    fn new(config: WorkerConfiguration, ias: Arc<IAS>, storage: Arc<StorageBackend>) -> Self {
        let (contract, identity_proof) =
            Self::create_contract(&config.contract_filename, ias, config.saved_identity_path);

        Self {
            contract,
            storage,
            identity_proof,
            ins: instrumentation::WorkerMetrics::new(),
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

    fn call_contract_batch_fallible(
        &mut self,
        batch: &CallBatch,
        root_hash: &H256,
    ) -> Result<(OutputBatch, H256)> {
        // Run in storage context.
        let (new_state_root, outputs) =
            self.contract
                .with_storage(self.storage.clone(), root_hash, || {
                    // Execute batch.
                    let _enclave_timer = self.ins.req_time_enclave.start_timer();
                    self.contract.contract_call_batch(batch)
                })?;

        Ok((outputs?, new_state_root))
    }

    /// Handle RPC call.
    fn handle_rpc_call(&self, request: Vec<u8>) -> BytesResult {
        // TODO: Notify enclave that it is stateless so it can clear storage cache.

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
        let result = self.call_contract_batch_fallible(&calls, &block.header.state_root);

        match result {
            Ok((outputs, new_state_root)) => {
                // No errors, hand over the batch to consensus.
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
    /// Optional saved identity path.
    pub saved_identity_path: Option<PathBuf>,
    /// Time limit for forwarded gRPC calls. If an RPC takes longer
    /// than this, we treat it as failed.
    pub forwarded_rpc_timeout: Option<Duration>,
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
        storage: Arc<StorageBackend>,
    ) -> Self {
        // Setup enclave RPC routing.
        // TODO: This sets up the routing globally, we should set it up the same as storage.
        {
            let mut router = RpcRouter::get_mut();

            // Key manager endpoint.
            if let Some(ref key_manager) = config.key_manager {
                router.add_handler(handlers::ContractForwarder::new(
                    ClientEndpoint::KeyManager,
                    grpc_environment.clone(),
                    config.forwarded_rpc_timeout,
                    key_manager.host.clone(),
                    key_manager.port,
                ));
            }
        }

        // Spawn inner worker in a separate thread.
        let (command_sender, command_receiver) = channel();
        thread::spawn(move || {
            WorkerInner::new(config, ias, storage).work(command_receiver);
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
