#[macro_use]
extern crate clap;
extern crate futures;
extern crate rand;

#[macro_use]
extern crate client_utils;
extern crate ekiden_core;
extern crate ekiden_rpc_client;
extern crate ekiden_runtime_client;

extern crate test_db_encryption_api;

use clap::{App, Arg};
use futures::Future;
use std::env::current_exe;
use std::fs::File;
use std::io::prelude::*;

use ekiden_runtime_client::create_runtime_client;
use test_db_encryption_api::with_api;

with_api! {
    create_runtime_client!(test_db_encryption, test_db_encryption_api, api);
}

fn main() {
    println!("[test_db_encryption] Hello from DB encryption test client!");

    let client = runtime_client!(test_db_encryption);

    println!("[test_db_encryption] Setting KM enclave...");

    // Get path to the key manager's mrenclave file.
    //
    // TODO: Once the `runtime_client!` macro supports custom app arguments
    // (see issue #1052), the key manager's mrenclave should be given as a
    // command-line argument instead.
    let mut mrenclave_path = current_exe().unwrap();
    mrenclave_path.pop(); // Pop executable name.
    mrenclave_path.pop(); // Pop debug/release build dir.
    mrenclave_path.push("enclave");
    mrenclave_path.push("ekiden-keymanager-trusted.mrenclave");

    let mut km_mrenclave = String::new();
    File::open(mrenclave_path.as_path())
        .expect("Key manager mrenclave file not found -- have you built the enclave with '--output-identity'?")
        .read_to_string(&mut km_mrenclave)
        .expect("An error occurred while reading the key manager mrenclave file.");
    km_mrenclave = km_mrenclave.trim().to_string();

    println!("[test_db_encryption] KM enclave is '{}'.", km_mrenclave);

    // First, set the key manager's enclave.
    let mut r_km = test_db_encryption::SetKMEnclaveRequest::new();
    r_km.set_mrenclave(km_mrenclave);

    client.set_km_enclave(r_km).wait().unwrap();

    println!("[test_db_encryption] Storing with encryption...");

    // Now try storing something with encryption.
    let mut r_se = test_db_encryption::StoreEncryptedRequest::new();
    r_se.set_key(String::from("top secret"));
    r_se.set_value(String::from("hello world!"));

    let response_se = client.store_encrypted(r_se).wait().unwrap();

    if response_se.get_ok() != true {
        panic!("Failed to store a key-value pair with encryption!");
    }

    println!("[test_db_encryption] Fetching with encryption...");

    // Fetch it back and see if it's the same.
    let mut r_fe = test_db_encryption::FetchEncryptedRequest::new();
    r_fe.set_key(String::from("top secret"));

    let response_fe = client.fetch_encrypted(r_fe).wait().unwrap();

    if response_fe.get_ok() != true {
        panic!("Failed to fetch a key-value pair with encryption!");
    }

    if response_fe.get_value() != String::from("hello world!") {
        panic!("Fetched value doesn't match stored value!");
    }

    println!("[test_db_encryption] Simple DB encryption test passed.");
}
