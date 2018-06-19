//! Dummy backend.
use std::sync::Arc;

use ekiden_beacon_api::create_beacon;
use ekiden_beacon_base::{BeaconService, RandomBeacon};
use ekiden_common::environment::Environment;
use ekiden_consensus_api::create_consensus;
use ekiden_consensus_base::{ConsensusBackend, ConsensusService};
use ekiden_consensus_dummy::DummyConsensusBackend;
use ekiden_core::error::Result;
use ekiden_di;
use ekiden_epochtime;
use ekiden_epochtime::interface::TimeSourceNotifier;
use ekiden_node_dummy_api::create_dummy_debug;
use ekiden_registry_api::{create_contract_registry, create_entity_registry};
use ekiden_registry_base::{ContractRegistryBackend, ContractRegistryService,
                           EntityRegistryBackend, EntityRegistryService};
use ekiden_registry_dummy::{DummyContractRegistryBackend, DummyEntityRegistryBackend};
use ekiden_scheduler_api::create_scheduler;
use ekiden_scheduler_base::{Scheduler, SchedulerService};
use ekiden_scheduler_dummy::DummySchedulerBackend;
use ekiden_storage_api::create_storage;
use ekiden_storage_base::{StorageBackend, StorageService};

use grpcio::{ChannelBuilder, Server, ServerBuilder};

use super::service::DebugService;

/// Dummy Backend configuration.
pub struct DummyBackendConfiguration {
    /// gRPC server port.
    pub port: u16,
}

/// Random Beacon, Consensus, Registry and Storage backends.
pub struct DummyBackend {
    /// Time source notifier.
    pub time_notifier: Arc<TimeSourceNotifier>,
    /// Random beacon.
    pub random_beacon: Arc<RandomBeacon>,
    /// Contract registry.
    pub contract_registry: Arc<ContractRegistryBackend>,
    /// Entity registry.
    pub entity_registry: Arc<EntityRegistryBackend>,
    /// Scheduler.
    pub scheduler: Arc<Scheduler>,
    /// Storage.
    pub storage: Arc<StorageBackend>,
    /// Consensus.
    pub consensus: Arc<ConsensusBackend>,

    grpc_server: Server,
}

impl DummyBackend {
    /// Create a new dummy backend bundle.
    pub fn new(
        config: DummyBackendConfiguration,
        mut di_container: ekiden_di::Container,
    ) -> Result<Self> {
        let env = di_container.inject::<Environment>()?;
        let time_notifier = di_container.inject::<TimeSourceNotifier>()?;
        let random_beacon = di_container.inject::<RandomBeacon>()?;
        let contract_registry = Arc::new(DummyContractRegistryBackend::new());
        let grpc_environment = env.grpc();

        let entity_registry = Arc::new(DummyEntityRegistryBackend::new(
            time_notifier.clone(),
            env.clone(),
        ));
        let scheduler = Arc::new(DummySchedulerBackend::new(
            env.clone(),
            random_beacon.clone(),
            contract_registry.clone(),
            entity_registry.clone(),
            time_notifier.clone(),
        ));

        let storage = di_container.inject::<StorageBackend>()?;

        let consensus = Arc::new(DummyConsensusBackend::new(
            env.clone(),
            scheduler.clone(),
            storage.clone(),
            contract_registry.clone(),
        ));

        let server_builder = ServerBuilder::new(grpc_environment.clone());

        let beacon_service = create_beacon(BeaconService::new(random_beacon.clone()));
        let contract_service =
            create_contract_registry(ContractRegistryService::new(contract_registry.clone()));
        let entity_service =
            create_entity_registry(EntityRegistryService::new(entity_registry.clone()));
        let scheduler_service = create_scheduler(SchedulerService::new(scheduler.clone()));
        let storage_service = create_storage(StorageService::new(storage.clone()));
        let consensus_service = create_consensus(ConsensusService::new(consensus.clone()));

        let localtime = ekiden_epochtime::local::get_local_time();
        let debug_service = {
            let mock = localtime.mock.lock().unwrap();
            let local_notifier = localtime.notifier.lock().unwrap();
            create_dummy_debug(DebugService::new(
                env.clone(),
                mock.clone(),
                local_notifier.clone(),
            ))
        };

        let server = server_builder
            .channel_args(
                ChannelBuilder::new(grpc_environment.clone())
                    .max_receive_message_len(i32::max_value())
                    .max_send_message_len(i32::max_value())
                    .build_args(),
            )
            .bind("0.0.0.0", config.port)
            .register_service(beacon_service)
            .register_service(contract_service)
            .register_service(entity_service)
            .register_service(scheduler_service)
            .register_service(storage_service)
            .register_service(consensus_service)
            .register_service(debug_service)
            .build()?;

        Ok(Self {
            time_notifier,
            random_beacon,
            contract_registry,
            entity_registry,
            scheduler,
            storage,
            consensus,
            grpc_server: server,
        })
    }

    /// Start the backend tasks.
    pub fn start(&mut self) {
        // Force-notify to bring the time-dependent backends to a sane state.
        {
            let localtime = ekiden_epochtime::local::get_local_time();
            let local_notifier = localtime.notifier.lock().unwrap();
            local_notifier.notify_subscribers().unwrap();
        }

        // Start the gRPC server.
        self.grpc_server.start();
        trace!("gRPC listeners: {:?}", self.grpc_server.bind_addrs());
    }
}
