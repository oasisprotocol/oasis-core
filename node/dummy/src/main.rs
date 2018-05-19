///! Dummy Shared Backend Node.
#[macro_use]
extern crate clap;
extern crate grpcio;
#[macro_use]
extern crate log;
extern crate pretty_env_logger;

extern crate ekiden_common;
extern crate ekiden_node_dummy;

use std::process::exit;
use std::sync::Arc;
use std::thread;

use clap::{App, Arg};
use log::LevelFilter;

use ekiden_common::epochtime::{MockTimeSource, SystemTimeSource};
use ekiden_node_dummy::backend::{DummyBackend, DummyBackendConfiguration, TimeSourceImpl};

const TIME_SOURCE_MOCK: &'static str = "mock";
const TIME_SOURCE_MOCK_RPC: &'static str = "mockrpc";
const TIME_SOURCE_SYSTEM: &'static str = "system";

fn main() {
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
        .arg(
            Arg::with_name("grpc-threads")
                .long("grpc-threads")
                .help("Number of threads to use for the event loop.")
                .default_value("4")
                .takes_value(true)
                .display_order(2),
        )
        .arg(
            Arg::with_name("time-source")
                .long("time-source")
                .help("Epoch Time implementation.")
                .default_value(TIME_SOURCE_SYSTEM)
                .possible_values(&[TIME_SOURCE_MOCK, TIME_SOURCE_MOCK_RPC, TIME_SOURCE_SYSTEM])
                .takes_value(true)
                .display_order(3),
        )
        .arg(
            Arg::with_name("mock-epoch-interval")
                .long("mock-epoch-interval")
                .help("Mock time epoch interval in seconds.")
                .default_value("600")
                .required_ifs(&[
                    ("time-source", TIME_SOURCE_MOCK),
                    ("time-source", TIME_SOURCE_MOCK_RPC),
                ])
                .takes_value(true)
                .display_order(4),
        )
        .arg(
            Arg::with_name("time-rpc-wait")
                .long("time-rpc-wait")
                .help("Wait on an RPC call before starting MockTime timer.")
                .requires_if("time-source", TIME_SOURCE_MOCK)
                .display_order(1),
        )
        .get_matches();

    // Initialize logger.
    pretty_env_logger::formatted_builder()
        .unwrap()
        .filter(None, LevelFilter::Trace)
        .init();

    // Setup the backends and gRPC service.
    trace!("Initializing backends/gRPC service.");
    let mock_epoch_interval = value_t!(matches, "mock-epoch-interval", u64).unwrap_or(600);
    let time_source_impl = match matches.value_of("time-source").unwrap() {
        TIME_SOURCE_MOCK => {
            let ts = Arc::new(MockTimeSource::new());
            let should_wait = matches.is_present("time-rpc-wait");
            TimeSourceImpl::Mock((ts, mock_epoch_interval, should_wait))
        }
        TIME_SOURCE_MOCK_RPC => {
            let ts = Arc::new(MockTimeSource::new());
            TimeSourceImpl::MockRPC((ts, mock_epoch_interval))
        }
        TIME_SOURCE_SYSTEM => TimeSourceImpl::System(Arc::new(SystemTimeSource {})),
        _ => panic!("Invalid time source specified."),
    };

    let mut backends = match DummyBackend::new(
        DummyBackendConfiguration {
            grpc_threads: value_t!(matches, "grpc-threads", usize).unwrap(),
            port: value_t!(matches, "port", u16).unwrap(),
        },
        time_source_impl,
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

    trace!("Parking main thread.");
    loop {
        thread::park();
    }
}
