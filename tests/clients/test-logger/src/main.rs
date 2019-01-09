#[macro_use]
extern crate clap;

#[macro_use]
extern crate client_utils;
extern crate ekiden_core;
extern crate ekiden_rpc_client;
extern crate ekiden_runtime_client;
extern crate log;

extern crate serde_json;
extern crate test_logger_api;

use clap::{App, Arg};

use ekiden_core::tokio;
use ekiden_runtime_client::create_runtime_client;
use test_logger_api::with_api;

with_api! {
    create_runtime_client!(test_logger, test_logger_api, api);
}

fn main() {
    println!("This is test-logger client!");

    println!("Initializaing test-logger runtime!");
    let client = runtime_client!(test_logger);
    let mut runtime = tokio::runtime::Runtime::new().unwrap();

    // log messages remotely
    println!(
        "The following log messages should appear on the worker side by calling error!, \
         warn!, info!, debug!, and trace! macros."
    );

    println!("Sending \"hello_error\" request to runtime on error level");
    runtime
        .block_on(client.write_error(String::from("hello_error")))
        .unwrap();

    println!("Sending \"hello_warn\" request to runtime on warn level");
    runtime
        .block_on(client.write_warn(String::from("hello_warn")))
        .unwrap();

    println!("Sending \"hello_info\" request to runtime on info level");
    runtime
        .block_on(client.write_info(String::from("hello_info")))
        .unwrap();

    println!("Sending \"hello_debug\" request to runtime on debug level");
    runtime
        .block_on(client.write_debug(String::from("hello_debug")))
        .unwrap();

    println!("Sending \"hello_trace\" request to runtime on trace level");
    runtime
        .block_on(client.write_trace(String::from("hello_trace")))
        .unwrap();

    let new_level = log::LevelFilter::Error;
    println!("Now setting max level to {}.", new_level);
    runtime
        .block_on(client.set_max_level(new_level.to_string()))
        .unwrap();

    println!("Sending \"hello_new_error\" request to runtime on error level");
    runtime
        .block_on(client.write_error(String::from("hello_new_error")))
        .unwrap();

    println!("Sending \"hello_new_warn\" request to runtime on warn level which should be omitted");
    runtime
        .block_on(client.write_warn(String::from("hello_new_warn")))
        .unwrap();

    println!("Sending \"hello_new_info\" request to runtime on info level");
    runtime
        .block_on(client.write_info(String::from("hello_new_info")))
        .unwrap();

    println!("Sending \"hello_new_debug\" request to runtime on debug level");
    runtime
        .block_on(client.write_debug(String::from("hello_new_debug")))
        .unwrap();

    println!("Sending \"hello_new_trace\" request to runtime on trace level");
    runtime
        .block_on(client.write_trace(String::from("hello_new_trace")))
        .unwrap();

    println!("Simple test-logger test passed.")
}
