#[macro_use]
extern crate clap;

#[macro_use]
extern crate client_utils;
extern crate ekiden_core;
extern crate ekiden_rpc_client;
extern crate ekiden_runtime_client;

extern crate test_logger_api;

use clap::{App, Arg};
use std::env::current_exe;
use std::fs::File;
use std::io::prelude::*;

use ekiden_core::tokio;
use ekiden_runtime_client::create_runtime_client;
use test_logger_api::with_api;

with_api! {
    create_runtime_client!(test_logger, test_logger_api, api);
}

fn main() {
    println!("[test_logger] Hello from the test-logger test client!");

    println!("[test_logger] Setting test-logger enclave...");

    let client = runtime_client!(test_logger);
    let mut runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(client.init()).unwrap();

    println!("[test_logger] done.");

    println!("[test_logger] Sending hello to trace!");
    runtime.block_on(client.write_trace(String::from("hello to trace"))).unwrap();

    println!("[test_logger] Sending hello to debug!");
    runtime.block_on(client.write_debug(String::from("hello to debug"))).unwrap();

    println!("[test_logger] Sending hello to info!");
    runtime.block_on(client.write_info(String::from("hello to info"))).unwrap();

    println!("[test_logger] Sending hello to warn!");
    runtime.block_on(client.write_warn(String::from("hello to warn"))).unwrap();

    println!("[test_logger] Sending hello to error!");
    runtime.block_on(client.write_error(String::from("hello to error"))).unwrap();

    println!("[test_logger] Simple test-logger test passed.")
}
