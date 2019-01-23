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
extern crate ekiden_keymanager_untrusted;
extern crate ekiden_rpc_api;
extern crate ekiden_tools;
extern crate ekiden_untrusted;

#[macro_use]
extern crate clap;
extern crate ekiden_storage_persistent;
extern crate pretty_env_logger;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{App, Arg};
use log::LevelFilter;

use ekiden_common::environment::{Environment, GrpcEnvironment};
use ekiden_common::x509;
use ekiden_keymanager_untrusted::backend;
use ekiden_keymanager_untrusted::node::{KeyManagerConfiguration, KeyManagerNode};

fn main() {
    let matches = App::new("Ekiden Key Manager Node")
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            Arg::with_name("port")
                .long("port")
                .short("p")
                .takes_value(true)
                .default_value("9003")
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
        .arg(
            Arg::with_name("tls-certificate")
                .long("tls-certificate")
                .takes_value(true)
                .help("Path to TLS certificate to use for gRPC (if it doesn't exist one will be generated)")
                .default_value("km-tls-certificate.pem")
                .required(true)
        )
        .arg(
            Arg::with_name("tls-key")
                .long("tls-key")
                .takes_value(true)
                .help("Path to TLS key to use for gRPC (if it doesn't exist one will be generated)")
                .default_value("km-tls-key.pem")
                .required(true)
        )
        .arg(
            Arg::with_name("storage-path")
                .long("storage-path")
                .help("Path to storage directory")
                .default_value("persistent_storage")
                .takes_value(true)
        )
        .get_matches();

    // Initialize logger.
    pretty_env_logger::formatted_builder()
        .unwrap()
        .filter(None, LevelFilter::Debug)
        .init();

    let environment: Arc<Environment> = Arc::new(GrpcEnvironment::default());
    let storage_path = PathBuf::from(matches.value_of("storage-path").unwrap());
    let storage_backend =
        Arc::new(ekiden_storage_persistent::PersistentStorageBackend::new(&storage_path).unwrap());
    let root_hash_path = storage_path.join("root-hash");

    // Load or generate TLS certificate.
    let (tls_certificate, tls_private_key) = x509::load_or_generate_certificate(
        matches.value_of("tls-certificate").expect("is required"),
        matches.value_of("tls-key").expect("is required"),
    ).expect("TLS credentials load must succeed");

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
                storage_backend: storage_backend,
                root_hash_path: root_hash_path,
            }
        },
        environment: environment.grpc(),
        tls_certificate,
        tls_private_key,
    }).expect("failed to initialize compute node");

    // Start the key manager.
    node.start();

    // Start the loop
    environment.start();
}
