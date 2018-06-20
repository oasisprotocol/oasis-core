///! Controller for the mockepoch contract.
extern crate ansi_term;
#[macro_use]
extern crate clap;
extern crate grpcio;

extern crate ekiden_common;
extern crate ekiden_di;
extern crate ekiden_ethereum;
extern crate ekiden_instrumentation_prometheus;

use std::process::exit;
use std::sync::Arc;

use ansi_term::Colour::Red;
use clap::{App, Arg, ArgMatches, SubCommand};

use ekiden_common::error::{Error, Result};
use ekiden_common::futures::Future;
use ekiden_di::Component;
use ekiden_ethereum::EthereumMockTimeViaWebsocket;

/// Tell the contract to change the epoch.
pub fn set_epoch(client: Arc<EthereumMockTimeViaWebsocket>, args: &ArgMatches) -> Result<()> {
    client
        .set_mock_time(value_t!(args, "epoch", u64)?, 0)
        .wait()?;

    Ok(())
}

fn main() {
    let matches = App::new("Ekiden Mock Epoch Contract Controller")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Oasis Labs Inc. <info@oasislabs.com>")
        .about("Controller for the mock epoch contract.")
        .subcommand(
            SubCommand::with_name("set-epoch")
                .about("Set current epoch")
                .arg(
                    Arg::with_name("epoch")
                        .long("epoch")
                        .short("e")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .arg(
            Arg::with_name("host")
                .long("host")
                .short("h")
                .default_value("127.0.0.1")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .short("p")
                .default_value("42261")
                .required(true)
                .takes_value(true),
        )
        .args(&known_components.get_arguments())
        .get_matches();

    // Create client.
    let mut known_components = ekiden_di::KnownComponents::new();
    ekiden_common::environment::GrpcEnvironment::register(&mut known_components);
    ekiden_instrumentation_prometheus::PrometheusMetricCollector::register(&mut known_components);
    ekiden_ethereum::web3_di::Web3Factory::register(&mut known_components);
    ekiden_ethereum::identity::EthereumEntityIdentity::register(&mut known_components);
    ekiden_ethereum::EthereumMockTime::register(&mut known_components);

    let mut container = known_components
        .build_with_arguments(&matches)
        .expect("failed to initialize component container");

    let client = container
        .inject::<EthereumMockTimeViaWebsocket>()
        .expect("Couldn't initialize connection to mock contract");

    let result = match matches.subcommand() {
        ("set-epoch", Some(args)) => set_epoch(client, args),
        _ => Err(Error::new("no command specified")),
    };
    match result {
        Ok(_) => {}
        Err(error) => {
            println!("{} {}", Red.bold().paint("error:"), error);
            exit(128);
        }
    }
}
