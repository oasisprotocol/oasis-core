//! Dummy backend.
use std::sync::Arc;
use std::time::{Duration, Instant};

use ekiden_beacon_api::create_beacon;
use ekiden_beacon_base::{BeaconService, RandomBeacon};
use ekiden_beacon_dummy::InsecureDummyRandomBeacon;
use ekiden_common::futures::{future, Executor, Future, GrpcExecutor, Stream};
use ekiden_common_api::create_time_source;
use ekiden_consensus_api::create_consensus;
use ekiden_consensus_base::{ConsensusBackend, ConsensusService};
use ekiden_consensus_dummy::DummyConsensusBackend;
use ekiden_core::epochtime::grpc::EpochTimeService;
use ekiden_core::epochtime::local::{LocalTimeSourceNotifier, MockTimeSource, SystemTimeSource};
use ekiden_core::epochtime::{TimeSource, EPOCH_INTERVAL};
use ekiden_core::error::{Error, Result};
use ekiden_di;
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

use futures_timer::{Interval, TimerHandle};
use grpcio::{ChannelBuilder, Environment, Server, ServerBuilder};

use super::service::DebugService;

/// EpochTime TimeSource backend.
pub enum TimeSourceImpl {
    /// Mock (configurable interval) epochs.
    Mock((Arc<MockTimeSource>, u64, bool)),

    /// Mock (service pumped) epochs.
    MockRPC((Arc<MockTimeSource>, u64)),

    /// System (RTC based) epochs.
    System(Arc<SystemTimeSource>),
}

/// Dummy Backend configuration.
pub struct DummyBackendConfiguration {
    /// Number of gRPC threads.
    pub grpc_threads: usize,
    /// gRPC server port.
    pub port: u16,
}

/// Random Beacon, Consensus, Registry and Storage backends.
pub struct DummyBackend {
    /// Time source notifier.
    pub time_notifier: Arc<LocalTimeSourceNotifier>,
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

    time_source: Arc<TimeSourceImpl>,
    grpc_environment: Arc<Environment>,
    grpc_server: Server,
}

impl DummyBackend {
    /// Create a new dummy backend bundle.
    pub fn new(
        config: DummyBackendConfiguration,
        time_source_impl: TimeSourceImpl,
        mut di_container: ekiden_di::Container,
    ) -> Result<Self> {
        let time_source: Arc<TimeSource> = match time_source_impl {
            TimeSourceImpl::Mock((ref ts, _, _)) => ts.clone(),
            TimeSourceImpl::MockRPC((ref ts, _)) => ts.clone(),
            TimeSourceImpl::System(ref ts) => ts.clone(),
        };
        let time_source_impl = Arc::new(time_source_impl);

        let time_notifier = Arc::new(LocalTimeSourceNotifier::new(time_source.clone()));

        let random_beacon = Arc::new(InsecureDummyRandomBeacon::new(time_notifier.clone()));
        let contract_registry = Arc::new(DummyContractRegistryBackend::new());
        let entity_registry = Arc::new(DummyEntityRegistryBackend::new(time_notifier.clone()));
        let scheduler = Arc::new(DummySchedulerBackend::new(
            random_beacon.clone(),
            contract_registry.clone(),
            entity_registry.clone(),
            time_notifier.clone(),
        ));

        let storage = di_container.inject::<StorageBackend>()?;

        let consensus = Arc::new(DummyConsensusBackend::new(
            scheduler.clone(),
            storage.clone(),
        ));

        let grpc_environment = Arc::new(Environment::new(config.grpc_threads));
        let server_builder = ServerBuilder::new(grpc_environment.clone());

        let time_service = create_time_source(EpochTimeService::new(time_source.clone()));
        let beacon_service = create_beacon(BeaconService::new(random_beacon.clone()));
        let contract_service =
            create_contract_registry(ContractRegistryService::new(contract_registry.clone()));
        let entity_service =
            create_entity_registry(EntityRegistryService::new(entity_registry.clone()));
        let scheduler_service = create_scheduler(SchedulerService::new(scheduler.clone()));
        let storage_service = create_storage(StorageService::new(storage.clone()));
        let consensus_service = create_consensus(ConsensusService::new(consensus.clone()));
        let debug_service = create_dummy_debug(DebugService::new(
            time_source_impl.clone(),
            time_notifier.clone(),
        ));

        let server = server_builder
            .channel_args(
                ChannelBuilder::new(grpc_environment.clone())
                    .max_receive_message_len(i32::max_value())
                    .max_send_message_len(i32::max_value())
                    .build_args(),
            )
            .bind("0.0.0.0", config.port)
            .register_service(time_service)
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
            time_source: time_source_impl,
            grpc_environment,
            grpc_server: server,
        })
    }

    /// Start the backend tasks.
    pub fn start(&mut self) {
        let mut executor = GrpcExecutor::new(self.grpc_environment.clone());

        self.random_beacon.start(&mut executor);
        self.entity_registry.start(&mut executor);
        self.scheduler.start(&mut executor);
        self.consensus.start(&mut executor);

        // Start the timer that drives the clock.
        match *self.time_source {
            TimeSourceImpl::Mock((ref ts, epoch_interval, wait_on_rpc)) => {
                // Start the mock epoch at 0.
                ts.set_mock_time(0, epoch_interval).unwrap();

                let (now, till) = ts.get_epoch().unwrap();
                if wait_on_rpc {
                    trace!("MockTime: Epoch: {} Till: {} (-> Wait)", now, till);
                } else {
                    trace!("MockTime: Epoch: {} Till: {}", now, till);
                    let dur = Duration::from_secs(epoch_interval);
                    executor.spawn({
                        let time_source = ts.clone();
                        let time_notifier = self.time_notifier.clone();

                        Box::new(
                            Interval::new(dur)
                                .map_err(|error| Error::from(error))
                                .for_each(move |_| {
                                    let (now, till) = time_source.get_epoch().unwrap();
                                    trace!("MockTime: Epoch: {} Till: {}", now + 1, till);
                                    time_source.set_mock_time(now + 1, till)?;
                                    time_notifier.notify_subscribers()
                                })
                                .then(|_| future::ok(())),
                        )
                    });
                }
            }
            TimeSourceImpl::MockRPC((ref ts, epoch_interval)) => {
                // Start the mock epoch at 0.
                ts.set_mock_time(0, epoch_interval).unwrap();

                let (now, till) = ts.get_epoch().unwrap();
                trace!("MockTimeRPC: Epoch: {} Till: {} (-> Wait)", now, till);

                // No timer, the entire operation is RPC dependent.
            }
            TimeSourceImpl::System(ref ts) => {
                let (now, till) = ts.get_epoch().unwrap();
                trace!("SystemTime: Epoch: {} Till: {}", now, till);

                // Note: This assumes that the underlying futures_timer
                // crate has relatively accurate time keeping, that the
                // host's idea of civil time is correct at startup, and
                // that timers are never early.
                //
                // This could be made more resilient to various
                // failures/misbehavior by periodically polling the
                // epoch (eg: once every 60s or so).

                let at = Instant::now() + Duration::from_secs(till);
                let dur = Duration::from_secs(EPOCH_INTERVAL);
                let timer = Interval::new_handle(at, dur, TimerHandle::default());

                executor.spawn({
                    let time_source = ts.clone();
                    let time_notifier = self.time_notifier.clone();

                    Box::new(
                        timer
                            .map_err(|error| Error::from(error))
                            .for_each(move |_| {
                                let (now, till) = time_source.get_epoch().unwrap();
                                trace!("SystemTime: Epoch: {} Till: {}", now, till);
                                time_notifier.notify_subscribers()
                            })
                            .then(|_| future::ok(())),
                    )
                });
            }
        };

        // Force-notify to bring the time-dependent backends to a sane state.
        self.time_notifier.notify_subscribers().unwrap();

        // Start the gRPC server.
        self.grpc_server.start();
        trace!("gRPC listeners: {:?}", self.grpc_server.bind_addrs());
    }
}
