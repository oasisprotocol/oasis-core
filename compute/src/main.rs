#![feature(use_extern_macros)]

extern crate sgx_types;

extern crate base64;
extern crate grpcio;
extern crate lru_cache;
extern crate protobuf;
extern crate reqwest;
extern crate thread_local;

extern crate hyper;
#[macro_use]
extern crate prometheus;

extern crate ekiden_compute_api;
extern crate ekiden_consensus_api;
extern crate ekiden_consensus_base;
extern crate ekiden_core;
extern crate ekiden_rpc_client;
extern crate ekiden_untrusted;

mod ias;
mod instrumentation;
mod handlers;
mod server;
mod worker;
mod node;

#[macro_use]
extern crate clap;

extern crate ekiden_consensus_dummy;

use std::path::Path;
use std::thread;

use clap::{App, Arg};

use self::ias::{IASConfiguration, SPID};
use self::node::{ComputeNode, ComputeNodeConfiguration};
use self::worker::{KeyManagerConfiguration, WorkerConfiguration};

fn main() {
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
        .arg(
            Arg::with_name("key-manager-host")
                .long("key-manager-host")
                .takes_value(true)
                .default_value("127.0.0.1"),
        )
        .arg(
            Arg::with_name("key-manager-port")
                .long("key-manager-port")
                .takes_value(true)
                .default_value("9003"),
        )
        .arg(
            Arg::with_name("consensus-backend")
                .long("consensus-backend")
                .takes_value(true)
                .default_value("dummy")
        )
        .arg(
            Arg::with_name("consensus-host")
                .long("consensus-host")
                .takes_value(true)
                .default_value("127.0.0.1"),
        )
        .arg(
            Arg::with_name("consensus-port")
                .long("consensus-port")
                .takes_value(true)
                .default_value("9002"),
        )
        .arg(Arg::with_name("disable-key-manager").long("disable-key-manager"))
        .arg(
            Arg::with_name("grpc-threads")
                .long("grpc-threads")
                .help("Number of threads to use in the GRPC server's HTTP server. Multiple threads only allow requests to be batched up. Requests will not be processed concurrently.")
                .default_value("1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("metrics-addr")
                .long("metrics-addr")
                .help("A SocketAddr (as a string) from which to serve metrics to Prometheus.")
                .takes_value(true)
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
                .help("Do not persist enclave identity (useful for contract development)")
        )
        .get_matches();

    // Setup consensus backend.
    // TODO: Change dummy backend to get computation group from another backend.
    let consensus_backend = Box::new(ekiden_consensus_dummy::DummyConsensusBackend::new(vec![]));

    // Setup compute node.
    let mut node = ComputeNode::new(ComputeNodeConfiguration {
        grpc_threads: value_t!(matches, "grpc-threads", usize).unwrap_or(1),
        port: value_t!(matches, "port", u16).unwrap_or(9001),
        consensus_backend,
        // IAS configuration.
        ias: if matches.is_present("ias-spid") {
            Some(IASConfiguration {
                spid: value_t!(matches, "ias-spid", SPID).unwrap_or_else(|e| e.exit()),
                pkcs12_archive: matches.value_of("ias-pkcs12").unwrap().to_string(),
            })
        } else {
            eprintln!("WARNING: IAS is not configured, validation will always return an error.");

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
                // TODO: Remove this after we switch to new storage backend.
                consensus_host: matches.value_of("consensus-host").unwrap().to_owned(),
                // TODO: Remove this after we switch to new storage backend.
                consensus_port: value_t!(matches, "consensus-port", u16).unwrap_or(9002),
                max_batch_size: value_t!(matches, "max-batch-size", usize).unwrap_or(1000),
                max_batch_timeout: value_t!(matches, "max-batch-timeout", u64).unwrap_or(1000),
                saved_identity_path: if matches.is_present("no-persist-identity") {
                    None
                } else {
                    Some(
                        Path::new(matches.value_of("identity-file").unwrap_or("identity.pb"))
                            .to_owned(),
                    )
                },
                // Key manager configuration.
                key_manager: if !matches.is_present("disable-key-manager") {
                    Some(KeyManagerConfiguration {
                        host: matches.value_of("key-manager-host").unwrap().to_owned(),
                        port: value_t!(matches, "key-manager-port", u16).unwrap_or(9003),
                    })
                } else {
                    None
                },
            }
        },
    }).expect("failed to initialize compute node");

    // Start compute node.
    node.start();

    // Start the Prometheus metrics endpoint.
    if let Ok(metrics_addr) = value_t!(matches, "metrics-addr", std::net::SocketAddr) {
        instrumentation::start_http_server(metrics_addr);
    }

    loop {
        thread::park();
    }
}
