///! Controller for the dummy shared backend node.
extern crate ansi_term;
#[macro_use]
extern crate clap;
extern crate grpcio;

extern crate ekiden_common;
extern crate ekiden_node_dummy;
extern crate ekiden_node_dummy_api;

use std::process::exit;
use std::sync::Arc;

use ansi_term::Colour::Red;
use clap::{App, Arg, ArgMatches, SubCommand};

use ekiden_common::error::{Error, Result};
use ekiden_node_dummy_api::{DummyDebugClient, SetEpochRequest};

/// Tell the dummy shared backend node to change the epoch.
pub fn set_epoch(client: DummyDebugClient, args: &ArgMatches) -> Result<()> {
    let mut request = SetEpochRequest::new();
    request.set_epoch(value_t!(args, "epoch", u64)?);

    client.set_epoch(&request)?;

    Ok(())
}

fn main() {
    let matches = App::new("Ekiden Dummy Shared Backend Node Controller")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Oasis Labs Inc. <info@oasislabs.com>")
        .about("Controller for the dummy shared backend node.")
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
        .get_matches();

    // Create client.
    let environment = Arc::new(grpcio::Environment::new(1));
    let channel = grpcio::ChannelBuilder::new(environment).connect(&format!(
        "{}:{}",
        matches.value_of("host").unwrap(),
        value_t!(matches, "port", u16).unwrap_or_else(|e| e.exit())
    ));
    let client = DummyDebugClient::new(channel);

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
