//! Compute node.
use std::sync::Arc;

use grpcio;

use ekiden_compute_api;
use ekiden_consensus_base::ConsensusBackend;
use ekiden_consensus_client::ConsensusClient;
use ekiden_core::address::Address;
use ekiden_core::bytes::B256;
use ekiden_core::contract::Contract;
use ekiden_core::entity::Entity;
use ekiden_core::error::Result;
use ekiden_core::futures::{Future, GrpcExecutor};
use ekiden_core::node::Node;
use ekiden_core::signature::Signed;
use ekiden_registry_base::{ContractRegistryBackend, EntityRegistryBackend,
                           REGISTER_CONTRACT_SIGNATURE_CONTEXT, REGISTER_ENTITY_SIGNATURE_CONTEXT,
                           REGISTER_NODE_SIGNATURE_CONTEXT};
use ekiden_registry_client::{ContractRegistryClient, EntityRegistryClient};
use ekiden_scheduler_base::Scheduler;
use ekiden_scheduler_client::SchedulerClient;
use ekiden_storage_frontend::StorageClient;
use ekiden_tools::get_contract_identity;

use super::consensus::{ConsensusConfiguration, ConsensusFrontend};
use super::group::ComputationGroup;
use super::ias::{IASConfiguration, IAS};
use super::services::computation_group::ComputationGroupService;
use super::services::web3::Web3Service;
use super::worker::{Worker, WorkerConfiguration};

/// Storage configuration.
// TODO: Add backend configuration.
pub struct StorageConfiguration;

/// Compute node configuration.
pub struct ComputeNodeConfiguration {
    /// Number of gRPC threads.
    pub grpc_threads: usize,
    /// gRPC server port.
    pub port: u16,
    /// Shared dummy node host.
    // TODO: Remove this once we handle backend configuration properly.
    pub dummy_host: String,
    /// Shared dummy node port.
    // TODO: Remove this once we handle backend configuration properly.
    pub dummy_port: u16,
    /// Number of compute replicas.
    // TODO: Remove this once we have independent contract registration.
    pub compute_replicas: u64,
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
        let ias = Arc::new(IAS::new(config.ias)?);

        // Create scheduler.
        // TODO: Base on configuration.
        let channel = grpcio::ChannelBuilder::new(grpc_environment.clone())
            .connect(&format!("{}:{}", config.dummy_host, config.dummy_port));
        let contract_registry = Arc::new(ContractRegistryClient::new(channel.clone()));
        let entity_registry = Arc::new(EntityRegistryClient::new(channel.clone()));
        let scheduler = Arc::new(SchedulerClient::new(channel.clone()));

        // Create storage backend.
        // TODO: Base on configuration.
        let storage_backend = Arc::new(StorageClient::new(channel.clone()));

        // Create consensus backend.
        // TODO: Base on configuration.
        let consensus_backend = Arc::new(ConsensusClient::new(channel.clone()));

        // Create contract.
        // TODO: Get this from somewhere.
        // TODO: This should probably be done independently?
        // TODO: We currently use the node key pair as the entity key pair.
        let contract_id =
            B256::from(get_contract_identity(config.worker.contract_filename.clone())?.as_slice());
        info!("Running compute node for contract {:?}", contract_id);
        let contract = {
            let mut contract = Contract::default();
            contract.id = contract_id;
            contract.replica_group_size = config.compute_replicas;
            contract.storage_group_size = 1;

            contract
        };
        let signed_contract = Signed::sign(
            &config.consensus.signer,
            &REGISTER_CONTRACT_SIGNATURE_CONTEXT,
            contract.clone(),
        );
        // XXX: Needed to avoid registering the key manager compute node for now.
        if config.worker.key_manager.is_some() {
            contract_registry.register_contract(signed_contract).wait()?;
        }

        // Register entity with the registry.
        // TODO: This should probably be done independently?
        // TODO: We currently use the node key pair as the entity key pair.
        let entity_pk = config.consensus.signer.get_public_key();
        let signed_entity = Signed::sign(
            &config.consensus.signer,
            &REGISTER_ENTITY_SIGNATURE_CONTEXT,
            Entity { id: entity_pk },
        );
        // XXX: Needed to avoid registering the key manager compute node for now.
        if config.worker.key_manager.is_some() {
            entity_registry.register_entity(signed_entity).wait()?;
        }

        // Register node with the registry.
        // TODO: Handle this properly, do not start any other services before registration is done.
        let node = Node {
            id: config.consensus.signer.get_public_key(),
            entity_id: entity_pk,
            expiration: 0xffffffffffffffff,
            addresses: Address::for_local_port(config.port)?,
            stake: vec![],
        };

        info!("Discovered compute node addresses: {:?}", node.addresses);

        let signed_node = Signed::sign(
            &config.consensus.signer,
            &REGISTER_NODE_SIGNATURE_CONTEXT,
            node,
        );
        // XXX: Needed to avoid registering the key manager compute node for now.
        if config.worker.key_manager.is_some() {
            info!("Registering compute node with the registry");
            entity_registry.register_node(signed_node).wait()?;
            info!("Compute node registration done");
        }

        // Create worker.
        let worker = Arc::new(Worker::new(
            config.worker,
            grpc_environment.clone(),
            ias,
            storage_backend,
        ));

        // Create computation group.
        let computation_group = Arc::new(ComputationGroup::new(
            contract_id,
            scheduler.clone(),
            entity_registry.clone(),
            config.consensus.signer.clone(),
            grpc_environment.clone(),
        ));

        // Create consensus frontend.
        let consensus_frontend = Arc::new(ConsensusFrontend::new(
            config.consensus,
            contract_id,
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
            consensus_backend,
            consensus_frontend,
            computation_group,
            server,
            executor: GrpcExecutor::new(grpc_environment),
        })
    }

    /// Start compute node.
    pub fn start(&mut self) {
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
