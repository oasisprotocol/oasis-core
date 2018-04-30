//! Compute node.
use std::sync::Arc;

use grpcio;

use ekiden_compute_api::create_compute;
use ekiden_consensus_base::ConsensusBackend;
use ekiden_core::error::Result;
use ekiden_core::futures::{Executor, Future};

use super::consensus::{ConsensusConfiguration, ConsensusFrontend};
use super::ias::{IASConfiguration, IAS};
use super::server::ComputeService;
use super::worker::{Worker, WorkerConfiguration};

/// Executor that uses the gRPC environment for execution.
struct GrpcExecutor(grpcio::Client);

impl GrpcExecutor {
    fn new(environment: Arc<grpcio::Environment>) -> Self {
        GrpcExecutor(
            // Create a dummy channel, needed for executing futures. This is required because
            // the API for doing this directly using an Executor is not exposed.
            grpcio::Client::new(grpcio::ChannelBuilder::new(environment).connect("")),
        )
    }
}

impl Executor for GrpcExecutor {
    fn spawn(&mut self, f: Box<Future<Item = (), Error = ()> + Send>) {
        self.0.spawn(f);
    }
}

/// Compute node configuration.
pub struct ComputeNodeConfiguration {
    /// Number of gRPC threads.
    pub grpc_threads: usize,
    /// gRPC server port.
    pub port: u16,
    /// Consensus configuration.
    pub consensus: ConsensusConfiguration,
    /// IAS configuration.
    pub ias: Option<IASConfiguration>,
    /// Worker configuration.
    pub worker: WorkerConfiguration,
}

/// Compute node.
pub struct ComputeNode {
    /// Consensus backend.
    consensus_backend: Arc<ConsensusBackend + Send + Sync>,
    /// Consensus frontend.
    consensus_frontend: Arc<ConsensusFrontend>,
    /// gRPC server.
    server: grpcio::Server,
    /// Futures executor used by this compute node.
    executor: GrpcExecutor,
}

impl ComputeNode {
    /// Create new compute node.
    pub fn new(config: ComputeNodeConfiguration) -> Result<Self> {
        // Create gRPC environment.
        let grpc_environment = Arc::new(grpcio::Environment::new(config.grpc_threads));

        // Create IAS.
        let ias = Arc::new(IAS::new(config.ias).unwrap());

        // Create worker.
        let worker = Arc::new(Worker::new(config.worker, grpc_environment.clone(), ias));

        // Create consensus frontend.
        let consensus_backend = config.consensus.backend.clone();
        let consensus_frontend = Arc::new(ConsensusFrontend::new(config.consensus, worker.clone()));

        // Create compute node gRPC server.
        let service = create_compute(ComputeService::new(worker, consensus_frontend.clone()));
        let server = grpcio::ServerBuilder::new(grpc_environment.clone())
            .register_service(service)
            .bind("0.0.0.0", config.port)
            .build()?;

        Ok(Self {
            consensus_backend,
            consensus_frontend,
            server,
            executor: GrpcExecutor::new(grpc_environment),
        })
    }

    /// Start compute node.
    pub fn start(&mut self) {
        // Start consensus backend tasks.
        self.consensus_backend.start(&mut self.executor);

        // Start consensus frontend tasks.
        self.consensus_frontend.start(&mut self.executor);

        // Start gRPC server.
        self.server.start();

        for &(ref host, port) in self.server.bind_addrs() {
            info!("Compute node listening on {}:{}", host, port);
        }
    }
}
