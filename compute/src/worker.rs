//! Worker process host.
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use rustracing::tag;
use rustracing_jaeger::span::SpanHandle;
use sgx_types;
use tempfile::{Builder, TempDir};
use tokio_process::{Child, CommandExt};
use tokio_uds;

use ekiden_core::bytes::H256;
use ekiden_core::enclave::api as identity_api;
use ekiden_core::environment::Environment;
use ekiden_core::error::{Error, Result};
use ekiden_core::futures::block_on;
use ekiden_core::futures::prelude::*;
use ekiden_core::rpc::client::ClientEndpoint;
use ekiden_core::runtime::batch::CallBatch;
use ekiden_core::tokio::timer::{Delay, Timeout};
use ekiden_core::x509::Certificate;
use ekiden_roothash_base::Block;
use ekiden_rpc_client::backend::{NetworkRpcClientBackend, RpcClientBackend};
use ekiden_storage_base::{InsertOptions, StorageBackend};
use ekiden_untrusted::enclave::identity::IAS;
use ekiden_worker_api::protocol::ShutdownNotify;
use ekiden_worker_api::types::ComputedBatch;
use ekiden_worker_api::{Host, HostHandler, Protocol, Worker};

/// Worker connect timeout (in seconds).
const WORKER_CONNECT_TIMEOUT: u64 = 5;
/// Worker respawn delay (in seconds).
const WORKER_RESPAWN_DELAY: u64 = 1;

/// Key manager configuration.
#[derive(Clone, Debug)]
pub struct KeyManagerConfiguration {
    /// Key manager node host.
    pub host: String,
    /// Key manager node port.
    pub port: u16,
    /// Key manager node certificate.
    pub cert: Certificate,
}

/// Worker prometheus configuration.
#[derive(Clone, Debug)]
pub struct PrometheusConfiguration {
    pub prometheus_metrics_addr: String,
    pub prometheus_push_interval: String,
    pub prometheus_push_job_name: String,
    pub prometheus_push_instance_label: String,
}

/// Worker tracing configuration.
#[derive(Clone, Debug)]
pub struct TracingConfiguration {
    pub sample_probability: String,
    pub agent_addr: String,
}

/// Worker configuration.
#[derive(Clone, Debug)]
pub struct WorkerConfiguration {
    /// Path to worker binary.
    pub worker_binary: String,
    /// Path to worker cache directory.
    pub cache_dir: String,
    /// Runtime binary filename.
    pub runtime_filename: String,
    /// Optional saved identity path.
    pub saved_identity_path: Option<PathBuf>,
    /// Time limit for forwarded gRPC calls. If an RPC takes longer
    /// than this, we treat it as failed.
    pub forwarded_rpc_timeout: Option<Duration>,
    /// Key manager configuration.
    pub key_manager: Option<KeyManagerConfiguration>,
    /// Prometheus configuration.
    pub prometheus: Option<PrometheusConfiguration>,
    /// Tracing configuration.
    pub tracing: Option<TracingConfiguration>,
}

struct WorkerProcess {
    /// Temporary worker directory.
    _worker_dir: TempDir,
    /// Worker process identifier.
    id: u32,
    /// Protocol instance.
    protocol: Protocol,
}

impl WorkerProcess {
    pub fn spawn(
        environment: Arc<Environment>,
        config: WorkerConfiguration,
        ias: Arc<IAS>,
        storage_backend: Arc<StorageBackend>,
    ) -> BoxFuture<(Self, Child, ShutdownNotify)> {
        // Bind listener and spawn worker process.
        let config_clone = config.clone();
        let bind_listener = future::lazy(move || {
            // Prepare host UNIX socket.
            let worker_dir = Builder::new().prefix("ekiden-worker").tempdir()?;
            let sock_path = worker_dir.path().join("host.sock");
            let listener = tokio_uds::UnixListener::bind(&sock_path)?;

            // Ensure cache directory exists.
            fs::create_dir_all(&config_clone.cache_dir)?;

            // Spawn worker process in a bubblewrap sandbox.
            // TODO: Generate and pass SECCOMP policy via a file descriptor.
            info!(
                "Spawning worker process \"{}\" in bubblewrap sandbox",
                config_clone.worker_binary
            );
            let child = Command::new("/usr/bin/bwrap")
                .arg("--unshare-all")
                // TODO: Proxy prometheus and tracing over an AF_LOCAL socket to avoid this.
                .arg("--share-net")
                .arg("--ro-bind")
                .arg("/etc/resolv.conf")
                .arg("/etc/resolv.conf")
                // Drop all capabilities.
                .arg("--cap-drop")
                .arg("ALL")
                // Ensure all workers have the same hostname.
                .arg("--hostname")
                .arg("ekiden-worker")
                // Forward /lib, /lib64, /opt and /usr/lib as read-only.
                .arg("--ro-bind")
                .arg("/lib")
                .arg("/lib")
                .arg("--ro-bind")
                .arg("/lib64")
                .arg("/lib64")
                .arg("--ro-bind")
                .arg("/opt") // Required for SGX libraries.
                .arg("/opt")
                .arg("--ro-bind")
                .arg("/usr/lib")
                .arg("/usr/lib")
                // Temporary directory.
                .arg("--tmpfs")
                .arg("/tmp")
                // A cut down /dev.
                .arg("--dev")
                .arg("/dev")
                // Worker directory is bound as /host (read-only).
                .arg("--ro-bind")
                .arg(&worker_dir.path())
                .arg("/host")
                // Cache directory is bound as /cache (writable).
                .arg("--bind")
                .arg(&config_clone.cache_dir)
                .arg("/cache")
                // Worker binary is bound as /worker (read-only).
                .arg("--ro-bind")
                .arg(&config_clone.worker_binary)
                .arg("/worker")
                // Runtime binary is bound as /runtime.so (read-only).
                .arg("--ro-bind")
                .arg(&config_clone.runtime_filename)
                .arg("/runtime.so")
                // Kill worker when node exits.
                .arg("--die-with-parent")
                // Start new terminal session.
                .arg("--new-session")
                // Change working directory to /.
                .arg("--chdir")
                .arg("/")
                .arg("--")
                // Arguments to worker process follow.
                .arg("/worker")
                .arg("--host-socket")
                .arg("/host/host.sock")
                .arg("--cache-dir")
                .arg("/cache")
                .args(if let Some(ref cfg) = config_clone.prometheus {
                    vec![
                        "--prometheus-mode".to_owned(),
                        "push".to_owned(),
                        "--prometheus-metrics-addr".to_owned(),
                        cfg.prometheus_metrics_addr.clone(),
                        "--prometheus-push-interval".to_owned(),
                        cfg.prometheus_push_interval.clone(),
                        "--prometheus-push-job-name".to_owned(),
                        cfg.prometheus_push_job_name.clone(),
                        "--prometheus-push-instance-label".to_owned(),
                        cfg.prometheus_push_instance_label.clone(),
                    ]
                } else {
                    vec![]
                })
                .args(if let Some(ref cfg) = config_clone.tracing {
                    vec![
                        "--tracing-enable".to_owned(),
                        "--tracing-sample-probability".to_owned(),
                        cfg.sample_probability.clone(),
                        "--tracing-agent-addr".to_owned(),
                        cfg.agent_addr.clone(),
                    ]
                } else {
                    vec![]
                })
                .arg("/runtime.so")
                .spawn_async()?;

            // Wait for the worker to connect.
            info!("Waiting for worker to connect");

            Ok((worker_dir, child, listener))
        });

        // Wait for the worker to connect.
        let socket = bind_listener.and_then(|(worker_dir, child, listener)| {
            let wait_for_connect = listener
                .incoming()
                .into_future()
                .map_err(|(error, _)| error.into())
                .and_then(move |(socket, _)| match socket {
                    Some(socket) => Ok((worker_dir, child, socket)),
                    None => Err(Error::new("worker failed to connect")),
                });

            // Timeout.
            Timeout::new(
                wait_for_connect,
                Duration::from_secs(WORKER_CONNECT_TIMEOUT),
            ).map_err(|error| {
                if error.is_elapsed() {
                    Error::new("worker connect timeout")
                } else if error.is_timer() {
                    error.into_timer().expect("error is timer error").into()
                } else {
                    error
                        .into_inner()
                        .expect("error is neither elapsed nor timer error")
                }
            })
        });

        // Setup the protocol handler.
        socket
            .and_then(move |(worker_dir, child, socket)| {
                // TODO: Ensure that our worker process connected and not someone else.
                info!("Worker connected");

                // Setup worker protocol.
                let protocol_handler = Arc::new(HostHandler(ProtocolHandler {
                    ias,
                    key_manager_client: config.key_manager.clone().map(|config_km| {
                        NetworkRpcClientBackend::new(
                            environment.clone(),
                            config.forwarded_rpc_timeout,
                            &config_km.host,
                            config_km.port,
                            config_km.cert,
                        ).expect("key manager rpc client creation must not fail")
                    }),
                    storage_backend,
                }));
                let (protocol, shutdown_signal) =
                    Protocol::new(environment.clone(), socket, protocol_handler);
                info!("Protocol handler started");

                Ok((
                    Self {
                        _worker_dir: worker_dir,
                        id: child.id(),
                        protocol,
                    },
                    child,
                    shutdown_signal,
                ))
            })
            .into_box()
    }

    fn rpc_call(&self, request: Vec<u8>) -> BoxFuture<Vec<u8>> {
        measure_counter_inc!("rpc_call_request");
        Worker::rpc_call(&self.protocol, request)
    }

    fn runtime_call_batch(
        &self,
        calls: CallBatch,
        block: Block,
        sh: SpanHandle,
        commit_storage: bool,
    ) -> BoxFuture<ComputedBatch> {
        measure_counter_inc!("runtime_call_request");
        let span = sh.child("send_runtime_call_batch", |opts| {
            opts.tag(tag::StdTag::span_kind("producer")).start()
        });

        // TODO: Transmit span handle identifier to worker to correlate requests.
        self.protocol
            .runtime_call_batch(calls, block, commit_storage)
            .then(move |result| {
                // Record end time and send to agent.
                drop(span);
                result
            })
            .into_box()
    }
}

struct Inner {
    /// Environment instance.
    environment: Arc<Environment>,
    /// Worker configuration.
    config: WorkerConfiguration,
    /// IAS instance.
    ias: Arc<IAS>,
    /// Storage backend instance.
    storage_backend: Arc<StorageBackend>,
    /// Currently active worker.
    worker: RwLock<Option<WorkerProcess>>,
}

/// Worker host.
pub struct WorkerHost {
    inner: Arc<Inner>,
}

struct ProtocolHandler {
    /// IAS instance.
    ias: Arc<IAS>,
    /// Current key manager client.
    key_manager_client: Option<NetworkRpcClientBackend>,
    /// Storage backend.
    storage_backend: Arc<StorageBackend>,
}

enum SuccessfulSpawn {
    /// Spawn succeeded in this iteration.
    Immediate(WorkerProcess, Child, ShutdownNotify),
    /// Spawn succeeded through a retry.
    Retried,
}

impl WorkerHost {
    /// Create a new worker host and spawn a child worker.
    pub fn new(
        environment: Arc<Environment>,
        config: WorkerConfiguration,
        ias: Arc<IAS>,
        storage_backend: Arc<StorageBackend>,
    ) -> Result<Self> {
        let instance = Self {
            inner: Arc::new(Inner {
                environment: environment.clone(),
                config,
                ias,
                storage_backend,
                worker: RwLock::new(None),
            }),
        };

        // Create the initial worker process (in a blocking manner).
        block_on(
            environment,
            WorkerHost::spawn_worker(instance.inner.clone()),
        )?;

        Ok(instance)
    }

    fn spawn_worker(inner: Arc<Inner>) -> BoxFuture<()> {
        // Spawn worker process.
        let shared_inner = inner.clone();
        let spawn_worker = WorkerProcess::spawn(
            inner.environment.clone(),
            inner.config.clone(),
            inner.ias.clone(),
            inner.storage_backend.clone(),
        ).map(|(worker, child, shutdown_signal)| {
            SuccessfulSpawn::Immediate(worker, child, shutdown_signal)
        })
            .or_else(move |error| {
                error!("Unable to spawn new worker process: {:?}", error);

                // Try respawning after a delay.
                Delay::new(Instant::now() + Duration::from_secs(WORKER_RESPAWN_DELAY))
                    .map_err(|error| error.into())
                    .and_then(move |_| {
                        info!("Respawning worker after {}s delay", WORKER_RESPAWN_DELAY);
                        Self::spawn_worker(shared_inner).map(|_| SuccessfulSpawn::Retried)
                    })
            });

        // Then prepare the shutdown signal handler.
        spawn_worker
            .and_then(move |spawn_result| {
                match spawn_result {
                    SuccessfulSpawn::Immediate(worker, mut child, shutdown_signal) => {
                        // Worker was spawned without any retries, setup shutdown signal handler.
                        let shared_inner = inner.clone();
                        spawn(
                            shutdown_signal
                                .then(move |_| {
                                    error!(
                                        "Worker connection terminated, ensuring process is dead"
                                    );

                                    // Take active worker, preventing any further calls to it. Kill the
                                    // process and wait for it to terminate.
                                    let worker = shared_inner
                                        .worker
                                        .write()
                                        .unwrap()
                                        .take()
                                        .expect("only we can take the worker");
                                    assert_eq!(worker.id, child.id());
                                    drop(child.kill());

                                    // Worker terminated, spawn a new one. This will also make the
                                    // newly spawned worker active.
                                    info!("Spawning new worker after termination");
                                    Self::spawn_worker(shared_inner.clone())
                                })
                                .discard(),
                        );

                        // Make the new worker active.
                        let mut active_worker = inner.worker.write().unwrap();
                        *active_worker = Some(worker);
                    }
                    SuccessfulSpawn::Retried => {
                        // Worker was spawned in a retry. We don't need to do anything as
                        // the retry handler already set everything up.
                    }
                }

                Ok(())
            })
            .into_box()
    }

    /// Queue an RPC call with the worker.
    ///
    /// Returns a receiver that will be used to deliver the response.
    pub fn rpc_call(&self, request: Vec<u8>) -> BoxFuture<Vec<u8>> {
        let worker_guard = self.inner.worker.read().unwrap();
        match worker_guard.as_ref() {
            Some(worker) => worker.rpc_call(request),
            None => future::err(Error::new("worker not ready")).into_box(),
        }
    }

    /// Request the worker to process a runtime call batch.
    pub fn runtime_call_batch(
        &self,
        calls: CallBatch,
        block: Block,
        sh: SpanHandle,
        commit_storage: bool,
    ) -> BoxFuture<ComputedBatch> {
        let worker_guard = self.inner.worker.read().unwrap();
        match worker_guard.as_ref() {
            Some(worker) => worker.runtime_call_batch(calls, block, sh, commit_storage),
            None => future::err(Error::new("worker not ready")).into_box(),
        }
    }
}

impl Host for ProtocolHandler {
    fn rpc_call(&self, endpoint: ClientEndpoint, request: Vec<u8>) -> BoxFuture<Vec<u8>> {
        match endpoint {
            ClientEndpoint::KeyManager => {
                // RPC call to key manager endpoint.
                match self.key_manager_client {
                    Some(ref client) => client.call_raw(request),
                    None => {
                        future::err(Error::new("key manager endpoint not supported")).into_box()
                    }
                }
            }
            endpoint => unimplemented!("RPC endpoint {:?} not implemented", endpoint),
        }
    }

    fn ias_get_spid(&self) -> BoxFuture<sgx_types::sgx_spid_t> {
        future::ok(self.ias.get_spid()).into_box()
    }

    fn ias_get_quote_type(&self) -> BoxFuture<sgx_types::sgx_quote_sign_type_t> {
        future::ok(self.ias.get_quote_type()).into_box()
    }

    fn ias_sigrl(&self, gid: &sgx_types::sgx_epid_group_id_t) -> BoxFuture<Vec<u8>> {
        // TODO: This should not be blocking as it can take some time.
        future::ok(self.ias.sigrl(gid)).into_box()
    }

    fn ias_report(&self, quote: Vec<u8>) -> BoxFuture<identity_api::AvReport> {
        // TODO: This should not be blocking as it can take some time.
        future::ok(self.ias.report(&quote)).into_box()
    }

    fn storage_get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        self.storage_backend.get(key)
    }

    fn storage_get_batch(&self, keys: Vec<H256>) -> BoxFuture<Vec<Option<Vec<u8>>>> {
        self.storage_backend.get_batch(keys)
    }

    fn storage_insert(&self, value: Vec<u8>, expiry: u64) -> BoxFuture<()> {
        self.storage_backend
            .insert(value, expiry, InsertOptions::default())
    }

    fn storage_insert_batch(&self, values: Vec<(Vec<u8>, u64)>) -> BoxFuture<()> {
        self.storage_backend
            .insert_batch(values, InsertOptions::default())
    }
}
