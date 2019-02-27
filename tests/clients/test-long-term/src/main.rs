#[macro_use]
extern crate clap;
extern crate log;

extern crate ekiden_core;
extern crate ekiden_rpc_client;
extern crate ekiden_runtime_client;

extern crate simple_keyvalue_api;

use std::{thread, time};

use clap::{App, Arg};
use log::info;

use ekiden_core::tokio;
use ekiden_runtime_client::create_runtime_client;
use simple_keyvalue_api::{with_api, KeyValue};

with_api! {
    create_runtime_client!(simple_keyvalue, simple_keyvalue_api, api);
}

fn main() {
    let args = ekiden_runtime_client::default_app!()
        .arg(
            Arg::with_name("mode")
                .long("mode")
                .help("client operation mode")
                .takes_value(true)
                .possible_values(&["sleep", "part1", "part2"])
                .default_value("sleep"),
        )
        .arg(
            Arg::with_name("sleep-for")
                .long("sleep-for")
                .help("amount of seconds to sleep for in sleep mode")
                .takes_value(true)
                .default_value("60"),
        )
        .get_matches();

    // Initialize tracing.
    ekiden_runtime_client::helpers::macros::report_forever("runtime-client", &args);

    let mode = args.value_of("mode").expect("mode argument is required");

    let client = ekiden_runtime_client::runtime_client!(simple_keyvalue, args);
    let mut runtime = tokio::runtime::Runtime::new().unwrap();

    if mode == "sleep" || mode == "part1" {
        info!("Inserting key/value pair");
        let kv = KeyValue {
            key: String::from("my_key"),
            value: String::from("my_value"),
        };
        let r = runtime.block_on(client.insert(kv)).unwrap();
        assert_eq!(r, None); // key should not exist in db before

        // Check value.
        info!("Checking if key exists and has the correct value");
        let r = runtime.block_on(client.get("my_key".to_string())).unwrap();
        assert_eq!(r.unwrap(), "my_value".to_string()); // key should exist in db
    }

    if mode == "sleep" {
        let sleep_for = value_t!(args.value_of("sleep-for"), u64).unwrap_or_else(|e| e.exit());

        // Sleep to allow for epoch to advance.
        info!("Sleeping for {} seconds", sleep_for);
        thread::sleep(time::Duration::from_secs(sleep_for));
    }

    if mode == "sleep" || mode == "part2" {
        // Check value again.
        info!("Checking (again) if key exists and has the correct value");
        let r = runtime.block_on(client.get("my_key".to_string())).unwrap();
        assert_eq!(r.unwrap(), "my_value".to_string()); // key should still exist in db
    }

    info!("All done");
}
