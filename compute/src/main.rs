#![feature(use_extern_macros)]
#![feature(clone_closures)]
#![feature(try_from)]

extern crate sgx_types;

extern crate base64;
extern crate grpcio;
#[macro_use]
extern crate log;
extern crate lru_cache;
extern crate protobuf;
extern crate reqwest;
extern crate serde_cbor;
extern crate thread_local;

extern crate ekiden_beacon_base;
extern crate ekiden_compute_api;
extern crate ekiden_consensus_base;
extern crate ekiden_core;
extern crate ekiden_registry_base;
extern crate ekiden_rpc_client;
extern crate ekiden_scheduler_base;
extern crate ekiden_storage_base;
extern crate ekiden_storage_batch;
extern crate ekiden_storage_multilayer;
extern crate ekiden_tools;
extern crate ekiden_untrusted;
#[macro_use]
extern crate ekiden_instrumentation;

mod consensus;
mod group;
mod ias;
mod node;
mod services;
mod worker;

// Everything above should be moved into a library, while everything below should be in the binary.

#[macro_use]
extern crate clap;
extern crate pretty_env_logger;

extern crate ekiden_consensus_client;
extern crate ekiden_consensus_dummy;
extern crate ekiden_di;
extern crate ekiden_epochtime;
extern crate ekiden_ethereum;
extern crate ekiden_instrumentation_prometheus;
extern crate ekiden_registry_client;
extern crate ekiden_scheduler_client;
extern crate ekiden_storage_frontend;

use std::path::Path;

use clap::{App, Arg};
use log::LevelFilter;

use ekiden_core::bytes::B256;
use ekiden_core::environment::Environment;
use ekiden_di::{Component, KnownComponents};

use self::consensus::{ConsensusConfiguration, ConsensusTestOnlyConfiguration};
use self::ias::{IASConfiguration, SPID};
use self::node::{ComputeNode, ComputeNodeConfiguration, ComputeNodeTestOnlyConfiguration};
use self::worker::WorkerConfiguration;

/// Register known components for dependency injection.
fn register_components(known_components: &mut KnownComponents) {
    // Environment.
    ekiden_core::environment::GrpcEnvironment::register(known_components);
    // Time.
    ekiden_ethereum::EthereumMockTimeViaWebsocket::register(known_components);
    ekiden_epochtime::local::LocalTimeSourceNotifier::register(known_components);
    // Storage.
    ekiden_storage_frontend::ImmediateClient::register(known_components);
    ekiden_storage_multilayer::MultilayerBackend::register(known_components);
    // Consensus.
    ekiden_consensus_client::ConsensusClient::register(known_components);
    ekiden_consensus_dummy::DummyConsensusSigner::register(known_components);
    // Scheduler.
    ekiden_scheduler_client::SchedulerClient::register(known_components);
    // Entity registry.
    ekiden_registry_client::EntityRegistryClient::register(known_components);
    // Contract registry.
    ekiden_registry_client::ContractRegistryClient::register(known_components);
    // Local identities.
    ekiden_ethereum::identity::EthereumEntityIdentity::register(known_components);
    ekiden_ethereum::identity::EthereumNodeIdentity::register(known_components);
    // Ethereum services.
    ekiden_ethereum::web3_di::Web3Factory::register(known_components);
    ekiden_ethereum::EthereumRandomBeaconViaWebsocket::register(known_components);
    // Instrumentation.
    ekiden_instrumentation_prometheus::PrometheusMetricCollector::register(known_components);
}

fn main() {
    // Create known components registry.
    let mut known_components = KnownComponents::new();
    register_components(&mut known_components);

    let matches = App::new("Ekiden Compute Node")
        .version("0.1.0")
        .author("Jernej Kos <jernej@kos.mx>")
        .about("Ekident compute node server")
        .arg(
            Arg::with_name("contract")
                .index(1)
                .value_name("CONTRACT")
                .help("Signed contract filename")
                .takes_value(true)
                .required(true)
                .display_order(1)
                .index(1),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .short("p")
                .takes_value(true)
                .default_value("9001")
                .display_order(2),
        )
        .arg(
            Arg::with_name("ias-spid")
                .long("ias-spid")
                .value_name("SPID")
                .help("IAS SPID in hex format")
                .takes_value(true)
                .requires("ias-pkcs12"),
        )
        .arg(
            Arg::with_name("ias-pkcs12")
                .long("ias-pkcs12")
                .help("Path to IAS client certificate and private key PKCS#12 archive")
                .takes_value(true)
                .requires("ias-spid"),
        )
        // TODO: Remove this once we have independent contract registration.
        .arg(
            Arg::with_name("compute-replicas")
                .long("compute-replicas")
                .help("Number of replicas in the computation group")
                .takes_value(true)
                .default_value("1"),
        )
        // TODO: Remove this once we have independent contract registration.
        .arg(
            Arg::with_name("compute-backup-replicas")
                .long("compute-backup-replicas")
                .help("Number of backup replicas in the computation group")
                .takes_value(true)
                .default_value("1"),
        )
        .arg(
            Arg::with_name("max-batch-size")
                .long("max-batch-size")
                .help("Maximum size of a batch of requests")
                .default_value("1000")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("max-batch-timeout")
                .long("max-batch-timeout")
                .help("Maximum timeout when waiting for a batch (in ms)")
                .default_value("1000")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("identity-file")
                .long("identity-file")
                .help("Path for saving persistent enclave identity")
                .default_value("identity.pb")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("no-persist-identity")
                .long("no-persist-identity")
                .help("Do not persist enclave identity (useful for contract development)"),
        )
        .arg(
            Arg::with_name("forwarded-rpc-timeout")
                .long("forwarded-rpc-timeout")
                .help("Time limit in seconds for forwarded gRPC calls. If an RPC takes longer than this, we treat it as failed.")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("test-inject-discrepancy")
                .long("test-inject-discrepancy")
                .help("TEST ONLY OPTION: inject discrepancy into consensus process")
                .hidden(true)
        )
        .arg(
            Arg::with_name("test-contract-id")
                .long("test-contract-id")
                .help("TEST ONLY OPTION: override contract identifier")
                .takes_value(true)
                .hidden(true)
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

    // Initialize component container.
    let mut container = known_components
        .build_with_arguments(&matches)
        .expect("failed to initialize component container");

    let environment = container.inject::<Environment>().unwrap();

    // Setup compute node.
    let mut node = ComputeNode::new(
        ComputeNodeConfiguration {
            port: value_t!(matches, "port", u16).unwrap_or(9001),
            // TODO: Remove this once we have independent contract registration.
            compute_replicas: value_t!(matches, "compute-replicas", u64)
                .unwrap_or_else(|e| e.exit()),
            // TODO: Remove this once we have independent contract registration.
            compute_backup_replicas: value_t!(matches, "compute-backup-replicas", u64)
                .unwrap_or_else(|e| e.exit()),
            // Consensus configuration.
            consensus: ConsensusConfiguration {
                max_batch_size: value_t!(matches, "max-batch-size", usize).unwrap_or(1000),
                max_batch_timeout: value_t!(matches, "max-batch-timeout", u64).unwrap_or(1000),
                test_only: ConsensusTestOnlyConfiguration {
                    inject_discrepancy: matches.is_present("test-inject-discrepancy"),
                },
            },
            // IAS configuration.
            ias: if matches.is_present("ias-spid") {
                Some(IASConfiguration {
                    spid: value_t!(matches, "ias-spid", SPID).unwrap_or_else(|e| e.exit()),
                    pkcs12_archive: matches.value_of("ias-pkcs12").unwrap().to_string(),
                })
            } else {
                warn!("IAS is not configured, validation will always return an error.");

                None
            },
            // Worker configuration.
            worker: {
                // Check if passed contract exists.
                let contract_filename = matches.value_of("contract").unwrap();
                if !Path::new(contract_filename).exists() {
                    panic!(format!("Could not find contract: {}", contract_filename))
                }

                WorkerConfiguration {
                    contract_filename: contract_filename.to_owned(),
                    saved_identity_path: if matches.is_present("no-persist-identity") {
                        None
                    } else {
                        Some(
                            Path::new(matches.value_of("identity-file").unwrap_or("identity.pb"))
                                .to_owned(),
                        )
                    },
                    forwarded_rpc_timeout: if matches.is_present("rpc-timeout") {
                        Some(std::time::Duration::new(
                            value_t_or_exit!(matches, "forwarded-rpc-timeout", u64),
                            0,
                        ))
                    } else {
                        None
                    },
                }
            },
            test_only: ComputeNodeTestOnlyConfiguration {
                contract_id: if matches.is_present("test-contract-id") {
                    Some(value_t_or_exit!(matches, "test-contract-id", B256))
                } else {
                    None
                },
            },
        },
        container,
    ).expect("failed to initialize compute node");

    // Start compute node.
    node.start();

    // Start the environment.
    environment.start();
}
