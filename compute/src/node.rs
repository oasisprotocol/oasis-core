//! Compute node.
use std::sync::Arc;

use grpcio;

use ekiden_beacon_base::RandomBeacon;
use ekiden_beacon_dummy::InsecureDummyRandomBeacon;
use ekiden_compute_api;
use ekiden_consensus_base::ConsensusBackend;
use ekiden_consensus_dummy::DummyConsensusBackend;
use ekiden_core::address::Address;
use ekiden_core::contract::Contract;
use ekiden_core::entity::Entity;
use ekiden_core::epochtime::{MockTimeSource, TimeSourceNotifier};
use ekiden_core::error::Result;
use ekiden_core::futures::{Executor, Future};
use ekiden_core::node::Node;
use ekiden_core::signature::Signed;
use ekiden_registry_base::{ContractRegistryBackend, EntityRegistryBackend,
                           REGISTER_CONTRACT_SIGNATURE_CONTEXT, REGISTER_ENTITY_SIGNATURE_CONTEXT,
                           REGISTER_NODE_SIGNATURE_CONTEXT};
use ekiden_registry_dummy::{DummyContractRegistryBackend, DummyEntityRegistryBackend};
use ekiden_scheduler_base::Scheduler;
use ekiden_scheduler_dummy::DummySchedulerBackend;
use ekiden_storage_dummy::DummyStorageBackend;

use super::consensus::{ConsensusConfiguration, ConsensusFrontend};
use super::group::ComputationGroup;
use super::ias::{IASConfiguration, IAS};
use super::services::computation_group::ComputationGroupService;
use super::services::web3::Web3Service;
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

/// Storage configuration.
// TODO: Add backend configuration.
pub struct StorageConfiguration;

/// Compute node configuration.
pub struct ComputeNodeConfiguration {
    /// Number of gRPC threads.
    pub grpc_threads: usize,
    /// gRPC server port.
    pub port: u16,
    /// Consensus configuration.
    pub consensus: ConsensusConfiguration,
    /// Storage configuration.
    pub storage: StorageConfiguration,
    /// IAS configuration.
    pub ias: Option<IASConfiguration>,
    /// Worker configuration.
    pub worker: WorkerConfiguration,
}

/// Compute node.
pub struct ComputeNode {
    /// Scheduler.
    scheduler: Arc<Scheduler>,
    /// Random beacon.
    beacon: Arc<RandomBeacon>,
    /// Consensus backend.
    consensus_backend: Arc<ConsensusBackend>,
    /// Consensus frontend.
    consensus_frontend: Arc<ConsensusFrontend>,
    /// Computation group.
    computation_group: Arc<ComputationGroup>,
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

        // Create scheduler.
        // TODO: Base on configuration.
        let time_source = Arc::new(MockTimeSource::new());
        let time_notifier = Arc::new(TimeSourceNotifier::new(time_source.clone()));
        time_notifier.notify_subscribers().unwrap();

        let beacon = Arc::new(InsecureDummyRandomBeacon::new(time_notifier.clone()));
        let entity_registry = Arc::new(DummyEntityRegistryBackend::new());
        let contract_registry = Arc::new(DummyContractRegistryBackend::new());
        let scheduler = Arc::new(DummySchedulerBackend::new(
            beacon.clone(),
            contract_registry.clone(),
            entity_registry.clone(),
            time_notifier,
        ));

        // Create contract.
        // TODO: Get this from somewhere.
        // TODO: This should probably be done independently?
        // TODO: We currently use the node key pair as the entity key pair.
        let contract = {
            let mut contract = Contract::default();
            contract.replica_group_size = 1;
            contract.storage_group_size = 1;

            contract
        };
        let signed_contract = Signed::sign(
            &config.consensus.signer,
            &REGISTER_CONTRACT_SIGNATURE_CONTEXT,
            contract.clone(),
        );
        contract_registry
            .register_contract(signed_contract)
            .wait()
            .unwrap();

        let contract = Arc::new(contract);

        // Register entity with the registry.
        // TODO: This should probably be done independently?
        // TODO: We currently use the node key pair as the entity key pair.
        let entity_pk = config.consensus.signer.get_public_key();
        let signed_entity = Signed::sign(
            &config.consensus.signer,
            &REGISTER_ENTITY_SIGNATURE_CONTEXT,
            Entity { id: entity_pk },
        );
        entity_registry
            .register_entity(signed_entity)
            .wait()
            .unwrap();

        // Register node with the registry.
        // TODO: Handle this properly, do not start any other services before registration is done.
        let node = Node {
            id: config.consensus.signer.get_public_key(),
            entity_id: entity_pk,
            expiration: 0xffffffffffffffff,
            addresses: Address::for_local_port(config.port).unwrap(),
            stake: vec![],
        };

        info!("Discovered compute node addresses: {:?}", node.addresses);

        let signed_node = Signed::sign(
            &config.consensus.signer,
            &REGISTER_NODE_SIGNATURE_CONTEXT,
            node,
        );
        info!("Registering compute node with the registry");
        entity_registry.register_node(signed_node).wait().unwrap();
        info!("Compute node registration done");

        // Create storage backend.
        // TODO: Base on configuration.
        let storage_backend = Arc::new(DummyStorageBackend::new());

        // Create consensus backend.
        // TODO: Base on configuration.
        let consensus_backend = Arc::new(DummyConsensusBackend::new(
            contract.clone(),
            scheduler.clone(),
            storage_backend.clone(),
        ));

        // Create worker.
        let worker = Arc::new(Worker::new(
            config.worker,
            grpc_environment.clone(),
            ias,
            storage_backend,
        ));

        // Create computation group.
        let computation_group = Arc::new(ComputationGroup::new(
            contract,
            scheduler.clone(),
            entity_registry.clone(),
            config.consensus.signer.clone(),
            grpc_environment.clone(),
        ));

        // Create consensus frontend.
        let consensus_frontend = Arc::new(ConsensusFrontend::new(
            config.consensus,
            worker.clone(),
            computation_group.clone(),
            consensus_backend.clone(),
        ));

        // Create compute node gRPC server.
        let web3 =
            ekiden_compute_api::create_web3(Web3Service::new(worker, consensus_frontend.clone()));
        let inter_node = ekiden_compute_api::create_computation_group(
            ComputationGroupService::new(consensus_frontend.clone()),
        );
        let server = grpcio::ServerBuilder::new(grpc_environment.clone())
            .register_service(web3)
            .register_service(inter_node)
            .bind("0.0.0.0", config.port)
            .build()?;

        Ok(Self {
            scheduler,
            beacon,
            consensus_backend,
            consensus_frontend,
            computation_group,
            server,
            executor: GrpcExecutor::new(grpc_environment),
        })
    }

    /// Start compute node.
    pub fn start(&mut self) {
        // Start random beacon tasks.
        self.beacon.start(&mut self.executor);

        // Start scheduler tasks.
        self.scheduler.start(&mut self.executor);

        // Start consensus backend tasks.
        self.consensus_backend.start(&mut self.executor);

        // Start consensus frontend tasks.
        self.consensus_frontend.start(&mut self.executor);

        // Start gRPC server.
        self.server.start();

        for &(ref host, port) in self.server.bind_addrs() {
            info!("Compute node listening on {}:{}", host, port);
        }

        // Start computation group services.
        self.computation_group.start(&mut self.executor);
    }
}
