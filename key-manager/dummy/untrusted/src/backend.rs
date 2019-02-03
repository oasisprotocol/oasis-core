use std::{
    borrow::Borrow,
    fmt::Write,
    ops::Deref,
    path::{Path, PathBuf},
    sync::{
        mpsc::{channel, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use grpcio::{RpcContext, RpcStatus, RpcStatusCode, UnarySink};
use protobuf::{self, Message};
use thread_local::ThreadLocal;

use ekiden_common::{bytes::H256, error::Result, hash::empty_hash};
use ekiden_core::{
    enclave::{api::IdentityProof, quote},
    error::Error,
    futures::{sync::oneshot, BoxFuture, Future, FutureExt},
    rpc::api,
};
use ekiden_rpc_api::{CallEnclaveRequest, CallEnclaveResponse, EnclaveRpc as EnclaveRpcAPI};
use ekiden_storage_base::StorageBackend;
use ekiden_untrusted::{
    enclave::ias::{IASConfiguration, IAS},
    Enclave, EnclaveDb, EnclaveIdentity, EnclaveRpc,
};

use exonum_rocksdb::DB;

static ROOT_HASH_KEY: &'static [u8] = b"key_manager_root_hash";

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
#[derive(Clone)]
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
    /// Storage backend for persisting the key-manager's enclave key store.
    pub storage_backend: Arc<StorageBackend>,
    /// Filesystem storage path. Used to locate the roothash db.
    pub root_hash_path: PathBuf,
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
                config.storage_backend,
                config.root_hash_path,
            )
            .unwrap()
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
    /// Storage backend used to enable enclave persistence.
    storage_backend: Arc<StorageBackend>,
    /// Database for the sole purpose of reading/writing a trie root hash,
    /// so that so that we can enable enclave persistence with the existing
    /// DatabaseHandle.
    root_hash_db: DB,
}

impl KeyManagerEnclave {
    fn new(
        contract_filename: &str,
        ias_config: Option<IASConfiguration>,
        saved_identity_path: Option<PathBuf>,
        storage_backend: Arc<StorageBackend>,
        root_hash_path: PathBuf,
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
            storage_backend: storage_backend.clone(),
            root_hash_db: DB::open_default(root_hash_path.as_path())
                .expect("Should always have a DB"),
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

        let enclave_response = self.enclave_rpc_call(enclave_request)?;

        match enclave_response.get_client_response().first() {
            Some(enclave_response) => Ok(enclave_response.write_to_bytes()?),
            None => Err(Error::new("no response to rpc call")),
        }
    }

    /// Performs the given enclave request in a storage context, ensuring to update the
    /// root hash at the end of each request.
    fn enclave_rpc_call(
        &self,
        enclave_request: api::EnclaveRequest,
    ) -> Result<api::EnclaveResponse> {
        // Read the current root hash so that we can access the enclave's database.
        let root_hash = self
            .root_hash_db
            .get(ROOT_HASH_KEY)
            .map_err(|e| Error::new(e.to_string()))
            .map(|result| match result {
                Some(hash) => H256::from_slice(&hash.to_vec()),
                None => empty_hash(),
            })?;

        let enclave_response =
            self.enclave
                .with_storage(self.storage_backend.clone(), &root_hash, || {
                    self.enclave.call(enclave_request)
                })?;

        // Update the root hash so that we read the updated database on the next rpc call.
        self.root_hash_db.put(ROOT_HASH_KEY, &enclave_response.0)?;

        enclave_response.1
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
