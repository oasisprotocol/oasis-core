use std::collections::HashMap;
use std::env;
use std::io::Read;
use std::marker::Send;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rustc_hex::FromHex;
use serde_json;
use web3;

use ekiden_common::error::Error;
use ekiden_common::futures::prelude::*;
use ekiden_common::tokio::timer::Interval;

/// The hard coded truffle development Ethereum address, taken from
/// http://truffleframework.com/docs/getting_started/console (entry 0).
pub const DEVELOPMENT_ADDRESS: &'static [u8] =
    b"\x62\x73\x06\x09\x0a\xba\xb3\xa6\xe1\x40\x0e\x93\x45\xbc\x60\xc7\x8a\x8b\xef\x57";

/// Start at truffle develop instance and return a handle for testing against.
pub fn start_truffle(cwd: &str) -> Child {
    if env::var("EXTERNAL_BLOCKCHAIN").is_ok() {
        Command::new("ls")
            .stdout(Stdio::null())
            .spawn()
            .expect("Odd")
    } else {
        let mut child = Command::new("truffle")
            .arg("develop")
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("Could not start truffle develop backend");
        // Block until output
        {
            let mut waiter = [0; 64];
            let stdout = child.stdout.as_mut();
            let _ = stdout.unwrap().read(&mut waiter);
        }
        child
    }
}

/// Deploy all existing contracts in the current truffle context, and
/// return a map of the contract name -> contract address.
///
/// WARNING: This expects the migration script to dump the contract
/// addresses to stdout in JSON format, which is non-standard behavior.
/// See: migrations/2_deploy_contracts.js
pub fn deploy_truffle(cwd: &str) -> HashMap<String, Vec<u8>> {
    let migrate = Command::new("truffle")
        .arg("migrate")
        .arg("--reset")
        .current_dir(cwd)
        .output()
        .unwrap();
    let output = String::from_utf8_lossy(&migrate.stdout);
    let contract_addresses = output
        .lines()
        .filter_map(|x| {
            if x.starts_with("CONTRACT_ADDRESSES: ") {
                Some(x.trim().rsplit(" ").next())
            } else {
                None
            }
        })
        .next()
        .expect(&format!("Truffle deployment failed: {:?}", output))
        .unwrap();

    // Parse the simple contract name -> hex address dictionary JSON.
    let contract_addresses: HashMap<String, String> =
        serde_json::from_str(contract_addresses).unwrap();
    let mut addresses = HashMap::new();
    for (contract, addr_hex) in &contract_addresses {
        let address = addr_hex.split_at(2).1.from_hex().unwrap();
        addresses.insert(contract.to_string(), address);
    }

    addresses
}

/// Run truffle test in the current working directory.
pub fn test_truffle(cwd: &str) {
    let status = Command::new("truffle")
        .arg("test")
        .arg("--network=test") // The `=` is mandatory, truffle bug?
        .current_dir(cwd)
        .status()
        .expect("truffle failed");
    assert!(status.success());
}

/// Make a stream of transactions between two truffle default accts to keep the chain going.
pub fn mine<T: 'static + web3::Transport + Sync + Send>(transport: T) -> BoxFuture<()>
where
    <T as web3::Transport>::Out: Send,
{
    Interval::new(Instant::now(), Duration::from_millis(500))
        .map_err(|_| ())
        .for_each(move |_| transport.execute("evm_mine", vec![]).discard())
        .map_err(|_| Error::new("internal error"))
        .into_box()
}
