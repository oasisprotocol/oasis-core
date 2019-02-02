//! A dummy client for testing purpose.
extern crate grpcio;
extern crate pretty_env_logger;
#[macro_use]
extern crate log;
#[macro_use]
extern crate clap;

extern crate ekiden_common;
extern crate ekiden_enclave_common;
extern crate ekiden_keymanager_client;
extern crate ekiden_keymanager_common;
extern crate ekiden_rpc_client;

use std::{process::exit, str::FromStr, sync::Arc, time::Duration};

use clap::{App, Arg};
use log::LevelFilter;

use ekiden_common::{
    environment::{Environment, GrpcEnvironment},
    x509,
};
use ekiden_enclave_common::quote::MrEnclave;
use ekiden_keymanager_client::{KeyManager, NetworkRpcClientBackendConfig};
use ekiden_keymanager_common::ContractId;

fn main() {
    let matches = App::new("Ekiden key manager client test")
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            Arg::with_name("host")
                .long("host")
                .takes_value(true)
                .default_value("127.0.0.1")
                .help("keymanager node host")
                .display_order(1),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .short("p")
                .takes_value(true)
                .default_value("9003")
                .help("keymanager node port")
                .display_order(2),
        )
        .arg(
            Arg::with_name("enclave")
                .long("mrenclave")
                .required(true)
                .takes_value(true)
                .help("keymanager MRENCLAVE")
                .display_order(3),
        )
        .arg(
            Arg::with_name("tls-certificate")
                .long("tls-certificate")
                .takes_value(true)
                .help("Path to TLS certificate to use for gRPC")
                .default_value("km-tls-certificate.pem")
                .required(true),
        )
        .get_matches();

    // Initialize logger.
    pretty_env_logger::formatted_builder()
        .unwrap()
        .filter(None, LevelFilter::Debug)
        .init();

    let keymanager_id =
        value_t!(matches.value_of("enclave"), MrEnclave).unwrap_or_else(|e| e.exit());

    // Load TLS certificate.
    let tls_certificate =
        x509::load_certificate_pem(matches.value_of("tls-certificate").expect("is required"))
            .expect("TLS credentials load must succeed");

    let environment: Arc<Environment> = Arc::new(GrpcEnvironment::default());

    let timeout = Some(Duration::new(5, 0));

    match KeyManager::instance() {
        Ok(mut keymanager) => {
            keymanager.configure_backend(NetworkRpcClientBackendConfig {
                environment: environment.clone(),
                timeout,
                host: value_t!(matches.value_of("host"), String).unwrap_or_else(|e| e.exit()),
                port: value_t!(matches.value_of("port"), u16).unwrap_or_else(|e| e.exit()),
                certificate: x509::Certificate::from_pem(&tls_certificate).unwrap(),
            });

            keymanager.set_contract(keymanager_id);
            debug!("Key manager MR_ENCLAVE set to {}", keymanager_id);

            let id_0 = ContractId::from_str(&"0".repeat(64)).unwrap();
            let id_1 = ContractId::from_str(&"1".repeat(64)).unwrap();
            let id_2 = ContractId::from_str(&"2".repeat(64)).unwrap();

            assert!(keymanager.get_or_create_secret_keys(id_1).is_err());
            assert!(keymanager.get_or_create_secret_keys(id_2).is_err());
            assert!(keymanager.get_public_key(id_0).is_ok());
            assert!(keymanager.get_public_key(id_1).is_err());
            assert!(keymanager.get_public_key(id_2).is_err());
            assert!(keymanager.long_term_public_key(id_0).is_ok());
            assert!(keymanager.long_term_public_key(id_1).is_err());
            assert!(keymanager.long_term_public_key(id_2).is_err());

            info!("Simple test passed.");
            exit(0);
        }
        Err(err) => {
            error!("Cannot get key manager instance: {}", err.description());
        }
    }

    environment.start();
}
