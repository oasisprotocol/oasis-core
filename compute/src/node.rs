//! Compute node.
use grpcio;
use std::sync::Arc;

use ekiden_compute_api;
use ekiden_consensus_base::{ConsensusBackend, ConsensusSigner};
use ekiden_core::bytes::B256;
use ekiden_core::contract::Contract;
use ekiden_core::environment::Environment;
use ekiden_core::error::Result;
use ekiden_core::futures::Future;
use ekiden_core::identity::{EntityIdentity, NodeIdentity};
use ekiden_core::signature::Signed;
use ekiden_di::Container;
use ekiden_registry_base::{ContractRegistryBackend, EntityRegistryBackend,
                           REGISTER_CONTRACT_SIGNATURE_CONTEXT, REGISTER_ENTITY_SIGNATURE_CONTEXT,
                           REGISTER_NODE_SIGNATURE_CONTEXT};
use ekiden_scheduler_base::Scheduler;
use ekiden_storage_api::create_storage;
use ekiden_storage_base::BatchStorage;
use ekiden_storage_base::{StorageBackend, StorageService};
use ekiden_tools::get_contract_identity;

use super::consensus::{ConsensusConfiguration, ConsensusFrontend};
use super::group::ComputationGroup;
use super::ias::{IASConfiguration, IAS};
use super::services::computation_group::ComputationGroupService;
use super::services::web3::Web3Service;
use super::worker::{Worker, WorkerConfiguration};

/// Compute node test-only configuration.
pub struct ComputeNodeTestOnlyConfiguration {
    /// Override contract identifier.
    pub contract_id: Option<B256>,
}

/// Compute node configuration.
pub struct ComputeNodeConfiguration {
    /// gRPC server port.
    pub port: u16,
    /// Number of compute replicas.
    // TODO: Remove this once we have independent contract registration.
    pub compute_replicas: u64,
    /// Number of compute backup replicas.
    // TODO: Remove this once we have independent contract registration.
    pub compute_backup_replicas: u64,
    /// Consensus configuration.
    pub consensus: ConsensusConfiguration,
    /// IAS configuration.
    pub ias: Option<IASConfiguration>,
    /// Worker configuration.
    pub worker: WorkerConfiguration,
    /// Test-only configuration.
    pub test_only: ComputeNodeTestOnlyConfiguration,
}

/// Compute node.
pub struct ComputeNode {
    /// storage.
    storage: Arc<StorageBackend>,
    /// gRPC server.
    server: grpcio::Server,
}

impl ComputeNode {
    /// Create new compute node.
    pub fn new(config: ComputeNodeConfiguration, mut container: Container) -> Result<Self> {
        // Create IAS.
        let ias = Arc::new(IAS::new(config.ias)?);

        let contract_registry = container.inject::<ContractRegistryBackend>()?;
        let entity_registry = container.inject::<EntityRegistryBackend>()?;
        let scheduler = container.inject::<Scheduler>()?;
        let storage_backend = container.inject::<BatchStorage>()?;
        let storage = container.inject::<StorageBackend>()?;
        let storage_service = create_storage(StorageService::new(storage.clone()));
        let consensus_backend = container.inject::<ConsensusBackend>()?;
        let consensus_signer = container.inject::<ConsensusSigner>()?;

        // Register entity with the registry.
        // TODO: This should probably be done independently?
        let entity_identity = container.inject::<EntityIdentity>()?;
        info!("Registering entity with the registry");
        entity_registry
            .register_entity(entity_identity.get_signed_entity(&REGISTER_ENTITY_SIGNATURE_CONTEXT))
            .wait()?;
        info!("Entity registration done");

        // Create contract.
        // TODO: Get this from somewhere.
        // TODO: This should probably be done independently?
        // TODO: We currently use the entity key pair as the contract key pair.
        let contract_id = match config.test_only.contract_id {
            Some(contract_id) => {
                warn!("Using manually overriden contract id");
                contract_id
            }
            None => B256::from(
                get_contract_identity(config.worker.contract_filename.clone())?.as_slice(),
            ),
        };

        info!("Running compute node for contract {:?}", contract_id);
        let contract = {
            let mut contract = Contract::default();
            contract.id = contract_id;
            contract.replica_group_size = config.compute_replicas;
            contract.replica_group_backup_size = config.compute_backup_replicas;
            contract.storage_group_size = 1;

            contract
        };
        let signed_contract = Signed::sign(
            &entity_identity.get_entity_signer(),
            &REGISTER_CONTRACT_SIGNATURE_CONTEXT,
            contract.clone(),
        );
        contract_registry.register_contract(signed_contract).wait()?;

        // Register node with the registry.
        let node_identity = container.inject::<NodeIdentity>()?;
        let signed_node = Signed::sign(
            &entity_identity.get_entity_signer(),
            &REGISTER_NODE_SIGNATURE_CONTEXT,
            node_identity.get_node(),
        );
        info!("Registering compute node with the registry");
        entity_registry.register_node(signed_node).wait()?;
        info!("Compute node registration done");

        // Environment.
        let environment = container.inject::<Environment>()?;
        let grpc_environment = environment.grpc();

        // Create worker.
        let worker = Arc::new(Worker::new(config.worker, ias, storage_backend.clone()));

        // Create computation group.
        let computation_group = Arc::new(ComputationGroup::new(
            contract_id,
            scheduler.clone(),
            entity_registry.clone(),
            environment.clone(),
            node_identity.clone(),
        ));

        // Create consensus frontend.
        let consensus_frontend = Arc::new(ConsensusFrontend::new(
            config.consensus,
            contract_id,
            environment.clone(),
            worker.clone(),
            computation_group.clone(),
            consensus_backend.clone(),
            consensus_signer.clone(),
            storage_backend.clone(),
        ));

        // Create compute node gRPC server.
        use grpcio::ClientCertificateRequestType::RequestClientCertificateButDontVerify;

        let web3 =
            ekiden_compute_api::create_web3(Web3Service::new(worker, consensus_frontend.clone()));
        let inter_node = ekiden_compute_api::create_computation_group(
            ComputationGroupService::new(consensus_frontend.clone()),
        );
        let server = grpcio::ServerBuilder::new(grpc_environment.clone())
            .channel_args(
                grpcio::ChannelBuilder::new(grpc_environment.clone())
                    .max_receive_message_len(i32::max_value())
                    .max_send_message_len(i32::max_value())
                    .build_args(),
            )
            .register_service(web3)
            .register_service(inter_node)
            .register_service(storage_service)
            .bind_secure(
                "0.0.0.0",
                config.port,
                grpcio::ServerCredentialsBuilder::new()
                    .root_cert(node_identity.get_tls_certificate().get_pem()?, true)
                    .client_certificate_request_type(RequestClientCertificateButDontVerify)
                    .add_cert(
                        node_identity.get_tls_certificate().get_pem()?,
                        node_identity.get_tls_private_key().get_pem()?,
                    )
                    .build(),
            )
            .build()?;

        Ok(Self { server, storage })
    }

    /// Start compute node.
    pub fn start(&mut self) {
        // Start gRPC server.
        self.server.start();

        for &(ref host, port) in self.server.bind_addrs() {
            info!("Compute node listening on {}:{}", host, port);
        }
    }
}
