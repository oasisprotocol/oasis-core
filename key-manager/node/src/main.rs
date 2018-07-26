#![feature(use_extern_macros)]
#![feature(try_from)]

extern crate sgx_types;

extern crate base64;
extern crate grpcio;
#[macro_use]
extern crate log;
extern crate lru_cache;
extern crate protobuf;
extern crate reqwest;
extern crate serde;
extern crate serde_cbor;
extern crate thread_local;

extern crate ekiden_common;
extern crate ekiden_di;
extern crate ekiden_keymanager_untrusted;
extern crate ekiden_rpc_api;
extern crate ekiden_tools;
extern crate ekiden_untrusted;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate clap;
extern crate pretty_env_logger;

use std::path::Path;

use clap::{App, Arg};
use log::LevelFilter;

use ekiden_common::environment::Environment;
use ekiden_common::identity::NodeIdentity;
use ekiden_di::Component;

use ekiden_keymanager_untrusted::backend;
use ekiden_keymanager_untrusted::node::{KeyManagerConfiguration, KeyManagerNode};

fn main() {
    let mut known_components = ekiden_di::KnownComponents::new();
    ekiden_common::environment::GrpcEnvironment::register(&mut known_components);
    ekiden_common::identity::LocalNodeIdentity::register(&mut known_components);
    ekiden_common::identity::LocalEntityIdentity::register(&mut known_components);

    let matches = App::new("Ekiden Key Manager Node")
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            Arg::with_name("port")
                .long("port")
                .short("p")
                .takes_value(true)
                .default_value("9001")
                .help("gRPC server port")
                .display_order(1),
        )
        .arg(
            Arg::with_name("enclave")
                .long("enclave")
                .takes_value(true)
                .default_value("/code/target/enclave/ekiden-keymanager-trusted.so")
                .help("Path to the key manager enclave")
                .display_order(2),
        )
        .args(&known_components.get_arguments())
        .get_matches();

    // Build components.
    let mut container = known_components
        .build_with_arguments(&matches)
        .expect("failed to initialize component container");

    // Initialize logger.
    pretty_env_logger::formatted_builder()
        .unwrap()
        .filter(None, LevelFilter::Debug)
        .init();

    let environment = container.inject::<Environment>().unwrap();
    let node_identity = container.inject::<NodeIdentity>().unwrap();

    // Setup a key manager node.
    let mut node = KeyManagerNode::new(KeyManagerConfiguration {
        // Port
        port: value_t!(matches, "port", u16).unwrap_or_else(|e| e.exit()),
        // Worker configuration.
        backend: {
            // Check if passed contract exists.
            let contract_filename = matches.value_of("enclave").unwrap();
            if !Path::new(contract_filename).exists() {
                error!("Cannot not find enclave: {}", contract_filename);
                return;
            }

            backend::BackendConfiguration {
                enclave_filename: contract_filename.to_owned(),
                ias: None,
                saved_identity_path: None,
                forwarded_rpc_timeout: None,
            }
        },
        environment: environment.grpc(),
        identity: node_identity.clone(),
    }).expect("failed to initialize compute node");

    // Start the key manager.
    node.start();

    // Start the loop
    environment.start();
}
