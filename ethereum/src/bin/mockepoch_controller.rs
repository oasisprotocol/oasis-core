///! Controller for the mockepoch contract.
extern crate ansi_term;
#[macro_use]
extern crate clap;
extern crate grpcio;
extern crate web3;

extern crate ekiden_common;
extern crate ekiden_di;
extern crate ekiden_ethereum;
extern crate ekiden_instrumentation_prometheus;

use std::process::exit;
use std::sync::Arc;

use ansi_term::Colour::Red;
use clap::{App, Arg, ArgMatches, SubCommand};
use web3::api::Web3;

use ekiden_common::bytes::H160;
use ekiden_common::environment::Environment;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::sync::oneshot;
use ekiden_common::futures::{Future, FutureExt};
use ekiden_common::identity::EntityIdentity;
use ekiden_di::Component;
use ekiden_ethereum::EthereumMockTimeViaWebsocket;

/// Tell the contract to change the epoch.
pub fn set_epoch(client: Arc<EthereumMockTimeViaWebsocket>, args: &ArgMatches) -> Result<()> {
    client
        .set_mock_time(value_t!(args, "epoch", u64)?, 0)
        .wait()?;

    Ok(())
}

pub fn mine(client: Arc<Web3<web3::transports::WebSocket>>, env: Arc<Environment>) -> Result<()> {
    let transport = client.transport().clone();
    let (s, r) = oneshot::channel::<()>();
    let fut = ekiden_ethereum::truffle::mine(transport);
    env.spawn(fut.then(move |_| s.send(())).into_box());
    let _ = r.wait();

    Ok(())
}

fn main() {
    let mut known_components = ekiden_di::KnownComponents::new();
    ekiden_common::environment::GrpcEnvironment::register(&mut known_components);
    ekiden_instrumentation_prometheus::PrometheusMetricCollector::register(&mut known_components);
    ekiden_ethereum::web3_di::Web3Factory::register(&mut known_components);
    ekiden_common::identity::LocalEntityIdentity::register(&mut known_components);
    ekiden_ethereum::EthereumMockTime::register(&mut known_components);

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
        .subcommand(SubCommand::with_name("mine").about("Mine on a truffle chain"))
        .args(&known_components.get_arguments())
        .get_matches();

    // Create client.
    let mut container = known_components
        .build_with_arguments(&matches)
        .expect("failed to initialize component container");

    let web3 = container
        .inject::<Web3<web3::transports::WebSocket>>()
        .expect("Failed to build Web3");
    let local_identity = container
        .inject::<EntityIdentity>()
        .expect("Failed to learn local identity");
    let environment = container
        .inject::<Environment>()
        .expect("Failed to build executor");

    let args = container.get_arguments().unwrap();
    let contract_address = value_t_or_exit!(args, "time-address", H160);

    let client = Arc::new(
        EthereumMockTimeViaWebsocket::new(
            web3.clone(),
            Arc::new(local_identity.get_entity()),
            contract_address,
            environment.clone(),
        ).expect("Failed to construct MockTime Client"),
    );

    let result = match matches.subcommand() {
        ("set-epoch", Some(args)) => set_epoch(client, args),
        ("mine", _) => mine(web3, environment.clone()),
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
