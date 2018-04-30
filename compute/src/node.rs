use std::sync::Arc;

use grpcio;

use ekiden_compute_api::create_compute;
use ekiden_consensus_base::ConsensusBackend;
use ekiden_core::error::Result;

use super::ias::{IASConfiguration, IAS};
use super::server::ComputeService;
use super::worker::{Worker, WorkerConfiguration};

/// Compute node configuration.
pub struct ComputeNodeConfiguration {
    /// Number of gRPC threads.
    pub grpc_threads: usize,
    /// gRPC server port.
    pub port: u16,
    /// Consensus backend.
    pub consensus_backend: Box<ConsensusBackend>,
    /// IAS configuration.
    pub ias: Option<IASConfiguration>,
    /// Worker configuration.
    pub worker: WorkerConfiguration,
}

/// Compute node.
pub struct ComputeNode {
    /// Consensus backend.
    consensus_backend: Box<ConsensusBackend>,
    /// gRPC server.
    server: grpcio::Server,
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

        // Create compute node gRPC server.
        let service = create_compute(ComputeService::new(worker.clone()));
        let server = grpcio::ServerBuilder::new(grpc_environment.clone())
            .register_service(service)
            .bind("0.0.0.0", config.port)
            .build()?;

        Ok(Self {
            consensus_backend: config.consensus_backend,
            server,
        })
    }

    /// Start compute node.
    pub fn start(&mut self) {
        self.server.start();

        for &(ref host, port) in self.server.bind_addrs() {
            // TODO: Use proper logging.
            println!("Compute node listening on {}:{}", host, port);
        }
    }
}
