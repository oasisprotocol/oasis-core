///! Dummy Shared Backend Node.
#[macro_use]
extern crate clap;
extern crate grpcio;
#[macro_use]
extern crate log;
extern crate pretty_env_logger;

extern crate ekiden_common;
extern crate ekiden_di;
use ekiden_di::Component;
extern crate ekiden_beacon_dummy;
extern crate ekiden_epochtime;
extern crate ekiden_ethereum;
extern crate ekiden_instrumentation_prometheus;
extern crate ekiden_node_dummy;
extern crate ekiden_storage_dummy;
extern crate ekiden_storage_dynamodb;
extern crate ekiden_storage_persistent;

use std::process::exit;

use clap::{App, Arg};
use log::LevelFilter;

use ekiden_common::environment::Environment;
use ekiden_node_dummy::backend::{DummyBackend, DummyBackendConfiguration};

fn main() {
    let mut known_components = ekiden_di::KnownComponents::new();
    ekiden_common::environment::GrpcEnvironment::register(&mut known_components);
    ekiden_storage_dummy::DummyStorageBackend::register(&mut known_components);
    ekiden_storage_dynamodb::DynamoDbBackend::register(&mut known_components);
    ekiden_storage_persistent::PersistentStorageBackend::register(&mut known_components);
    ekiden_beacon_dummy::InsecureDummyRandomBeacon::register(&mut known_components);
    ekiden_ethereum::web3_di::Web3Factory::register(&mut known_components);
    ekiden_ethereum::identity::EthereumEntityIdentity::register(&mut known_components);
    ekiden_epochtime::local::LocalTimeSourceNotifier::register(&mut known_components);
    ekiden_epochtime::local::MockTimeNotifier::register(&mut known_components);
    ekiden_epochtime::local::MockTimeRpcNotifier::register(&mut known_components);
    ekiden_ethereum::EthereumMockTime::register(&mut known_components);
    ekiden_ethereum::EthereumRandomBeaconViaWebsocket::register(&mut known_components);

    ekiden_instrumentation_prometheus::PrometheusMetricCollector::register(&mut known_components);

    let matches = App::new("Ekiden Dummy Shared Backend Node")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Oasis Labs Inc. <info@oasislabs.com>")
        .about("Provide backend services via dummy test interfaces, exposed as gRPC calls.")
        .arg(
            Arg::with_name("port")
                .long("port")
                .short("p")
                .takes_value(true)
                .default_value("42261")
                .display_order(1),
        )
        .args(&known_components.get_arguments())
        .get_matches();

    // Initialize logger.
    pretty_env_logger::formatted_builder()
        .unwrap()
        .filter(None, LevelFilter::Trace)
        .filter(Some("mio"), LevelFilter::Warn)
        .filter(Some("tokio_threadpool"), LevelFilter::Warn)
        .filter(Some("tokio_reactor"), LevelFilter::Warn)
        .filter(Some("tokio_io"), LevelFilter::Warn)
        .filter(Some("tokio_core"), LevelFilter::Warn)
        .filter(Some("web3"), LevelFilter::Info)
        .filter(Some("hyper"), LevelFilter::Warn)
        .init();

    let mut container = known_components
        .build_with_arguments(&matches)
        .expect("failed to initialize component container");

    let environment = container.inject::<Environment>().unwrap();

    // Setup the backends and gRPC service.
    trace!("Initializing backends/gRPC service.");

    let mut backends = match DummyBackend::new(
        DummyBackendConfiguration {
            port: value_t!(matches, "port", u16).unwrap(),
        },
        container,
    ) {
        Ok(backends) => backends,
        Err(err) => {
            error!("Failed to initialize backends: {}", err);
            exit(-1);
        }
    };

    // Start all the things.
    trace!("Starting all workers.");
    backends.start();

    // Start the environment.
    environment.start();
}
