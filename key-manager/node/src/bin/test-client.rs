/// A dummy client for testing purpose
extern crate ekiden_common;
extern crate ekiden_di;
extern crate ekiden_enclave_common;
extern crate ekiden_keymanager_client;
extern crate ekiden_keymanager_common;
extern crate ekiden_rpc_client;
extern crate grpcio;
extern crate pretty_env_logger;

#[macro_use]
extern crate log;
#[macro_use]
extern crate clap;

use clap::{App, Arg};
use log::LevelFilter;
use std::str::FromStr;
use std::time::Duration;

use ekiden_common::environment::Environment;
use ekiden_common::identity::NodeIdentity;
use ekiden_di::Component;
use ekiden_enclave_common::quote::MrEnclave;
use ekiden_keymanager_client::{KeyManager, NetworkRpcClientBackendConfig};
use ekiden_keymanager_common::{ContractId, PublicKeyType};

fn main() {
    let mut known_components = ekiden_di::KnownComponents::new();
    ekiden_common::environment::GrpcEnvironment::register(&mut known_components);
    ekiden_common::identity::LocalNodeIdentity::register(&mut known_components);
    ekiden_common::identity::LocalEntityIdentity::register(&mut known_components);

    let matches = App::new("Ekiden key Manager client test")
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            Arg::with_name("host")
                .long("host")
                .takes_value(true)
                .default_value("localhost")
                .help("keymanager node host")
                .display_order(1),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .short("p")
                .takes_value(true)
                .default_value("9001")
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
        .args(&known_components.get_arguments())
        .get_matches();

    // Initialize logger.
    pretty_env_logger::formatted_builder()
        .unwrap()
        .filter(None, LevelFilter::Debug)
        .init();

    // Build components.
    let mut container = known_components
        .build_with_arguments(&matches)
        .expect("failed to initialize component container");

    let keymanager_id =
        value_t!(matches.value_of("enclave"), MrEnclave).unwrap_or_else(|e| e.exit());

    let environment = container.inject::<Environment>().unwrap();
    let keymanager_identity = container.inject::<NodeIdentity>().unwrap();

    let timeout = Some(Duration::new(5, 0));

    match KeyManager::get() {
        Ok(mut keymanager) => {
            keymanager.configure_backend(NetworkRpcClientBackendConfig {
                environment: environment.clone(),
                timeout,
                host: value_t!(matches.value_of("host"), String).unwrap_or_else(|e| e.exit()),
                port: value_t!(matches.value_of("port"), u16).unwrap_or_else(|e| e.exit()),
                certificate: keymanager_identity.get_tls_certificate().to_owned(),
            });

            keymanager.set_contract(keymanager_id);
            debug!("backend MR_ENCLAVE set to {}", keymanager_id);

            let id_0 = ContractId::from_str(&"0".repeat(64)).unwrap();
            let id_1 = ContractId::from_str(&"1".repeat(64)).unwrap();
            let id_2 = ContractId::from_str(&"2".repeat(64)).unwrap();

            assert!(keymanager.get_or_create_secret_keys(id_1).is_err());
            assert!(keymanager.get_or_create_secret_keys(id_2).is_err());
            assert!(keymanager.get_public_key(id_0).is_ok());
            assert!(keymanager.get_public_key(id_1).is_err());
            assert!(keymanager.get_public_key(id_2).is_err());

            info!("simple test passed...")
        }
        Err(err) => {
            error!("cannot get key manager instance: {}", err.description());
        }
    }

    environment.start();
}
