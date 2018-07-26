use std::borrow::Borrow;
use std::fmt::Write;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use grpcio::{RpcContext, RpcStatus, RpcStatusCode, UnarySink};
use protobuf;
use protobuf::Message;
use thread_local::ThreadLocal;

use ekiden_common::error::Result;
use ekiden_core::enclave::api::IdentityProof;
use ekiden_core::enclave::quote;
use ekiden_core::error::Error;
use ekiden_core::futures::sync::oneshot;
use ekiden_core::futures::{BoxFuture, Future, FutureExt};
use ekiden_core::rpc::api;
use ekiden_rpc_api::{CallEnclaveRequest, CallEnclaveResponse, EnclaveRpc as EnclaveRpcAPI};
use ekiden_untrusted::enclave::ias::{IASConfiguration, IAS};
use ekiden_untrusted::{Enclave, EnclaveIdentity, EnclaveRpc};

/// Bytes
pub type Blob = Vec<u8>;
pub type BlobResult = Result<Blob>;
/// Result bytes sender part of the channel.
pub type BytesSender = oneshot::Sender<BlobResult>;

/// Command sent to the worker thread.
struct Command {
    payload: Vec<u8>,
    sender: BytesSender,
}

/// Key manager backend configuration.
#[derive(Clone, Debug)]
pub struct BackendConfiguration {
    /// Contract binary filename.
    pub enclave_filename: String,
    /// IAS configuration.
    pub ias: Option<IASConfiguration>,
    /// Optional saved identity path.
    pub saved_identity_path: Option<PathBuf>,
    /// Time limit for forwarded gRPC calls. If an RPC takes longer
    /// than this, we treat it as failed.
    pub forwarded_rpc_timeout: Option<Duration>,
}

/// Key manager worker which executes commands in secure enclaves.
pub struct KeyManagerInner {
    /// Channel for submitting commands to the worker.
    command_sender: Mutex<Sender<Command>>,
    /// Thread-local clone of the command sender which is required to avoid locking the
    /// mutex each time we need to send a command.
    tl_command_sender: ThreadLocal<Sender<Command>>,
}

impl KeyManagerInner {
    /// Create new enclave.
    pub fn new(config: BackendConfiguration) -> Self {
        // Spawn inner worker in a separate thread.
        let (command_sender, command_receiver) = channel();
        thread::spawn(move || {
            // Question: when is enclave destroyed?
            KeyManagerEnclave::new(
                &config.enclave_filename,
                config.ias,
                config.saved_identity_path,
            ).unwrap()
                .run(command_receiver);
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

    fn query_key_manager(&self, payload: Vec<u8>) -> BoxFuture<BlobResult> {
        let (response_sender, response_receiver) = oneshot::channel();
        self.get_command_sender()
            .send(Command {
                payload,
                sender: response_sender,
            })
            .unwrap();

        response_receiver
            .map_err(|_| Error::new("canceled"))
            .into_box()
    }
}

#[derive(Clone)]
pub struct KeyManager {
    inner: Arc<KeyManagerInner>,
}

impl KeyManager {
    pub fn new(config: BackendConfiguration) -> Self {
        KeyManager {
            inner: Arc::new(KeyManagerInner::new(config)),
        }
    }
}

impl EnclaveRpcAPI for KeyManager {
    // FIXME: duplicated code (but not identical)
    // similar to https://github.com/oasislabs/ekiden/blob/master/compute/src/services/enclaverpc.rs
    fn call_enclave(
        &self,
        ctx: RpcContext,
        req: CallEnclaveRequest,
        sink: UnarySink<CallEnclaveResponse>,
    ) {
        let response_receiver = self.inner.query_key_manager(req.get_payload().to_vec());

        // Prepare response future.
        let f = response_receiver.then(|result| match result {
            Ok(Ok(response)) => {
                let mut rpc_response = CallEnclaveResponse::new();
                rpc_response.set_payload(response);

                sink.success(rpc_response)
            }
            Ok(Err(error)) => sink.fail(RpcStatus::new(
                RpcStatusCode::Internal,
                Some(error.description().to_owned()),
            )),
            Err(error) => sink.fail(RpcStatus::new(
                RpcStatusCode::Internal,
                Some(error.description().to_owned()),
            )),
        });
        ctx.spawn(f.map_err(|_error| ()));
    }
}

struct KeyManagerEnclave {
    /// Contract running in an enclave.
    enclave: Enclave,
    /// Enclave identity proof.
    identity_proof: IdentityProof,
}

impl KeyManagerEnclave {
    fn new(
        contract_filename: &str,
        ias_config: Option<IASConfiguration>,
        saved_identity_path: Option<PathBuf>,
    ) -> Result<Self> {
        // Check if passed contract exists.
        if !Path::new(contract_filename).exists() {
            return Err(Error::new(format!(
                "Could not find contract: {}",
                contract_filename
            )));
        }

        let ias = Arc::new(IAS::new(ias_config)?);

        let (contract, identity_proof) =
            Self::create_contract(contract_filename, ias, saved_identity_path);

        Ok(Self {
            enclave: contract,
            identity_proof: identity_proof,
        })
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

    /// Handle RPC call.
    fn handle_rpc_call(&self, request: Vec<u8>) -> BlobResult {
        // process requests
        let mut enclave_request = api::EnclaveRequest::new();
        {
            let client_requests = enclave_request.mut_client_request();
            // TODO: Why doesn't enclave request contain bytes directly?
            let client_request = protobuf::parse_from_bytes(&request)?;
            client_requests.push(client_request);
        }

        let enclave_response = { self.enclave.call(enclave_request) }?;

        match enclave_response.get_client_response().first() {
            Some(enclave_response) => Ok(enclave_response.write_to_bytes()?),
            None => Err(Error::new("no response to rpc call")),
        }
    }

    /// Process requests from a receiver until the channel closes.
    fn run(&mut self, command_receiver: Receiver<Command>) {
        // Block for the next call.
        while let Ok(command) = command_receiver.recv() {
            let result = self.handle_rpc_call(command.payload);
            command.sender.send(result).unwrap();
        }
    }
}
