#[macro_use]
extern crate clap;
extern crate rand;

#[macro_use]
extern crate client_utils;
extern crate ekiden_core;
extern crate ekiden_runtime_client;
#[macro_use]
extern crate ekiden_instrumentation;
extern crate ekiden_rpc_client;

extern crate token_api;

use clap::{App, Arg};
use rand::{thread_rng, Rng};

use ekiden_core::tokio::runtime::current_thread::Runtime;
use ekiden_runtime_client::create_runtime_client;
use token_api::with_api;

with_api! {
    create_runtime_client!(token, token_api, api);
}

/// Initializes the token scenario.
fn init(client: &mut token::Client, _runs: usize, _threads: usize, runtime: &mut Runtime) {
    // Create new token contract.
    let mut request = token::CreateRequest::new();
    request.set_sender("bank".to_string());
    request.set_token_name("Ekiden Token".to_string());
    request.set_token_symbol("EKI".to_string());
    request.set_initial_supply(8);

    runtime.block_on(client.create(request)).unwrap();

    // Check balances.
    let response = runtime
        .block_on(client.get_balance({
            let mut request = token::GetBalanceRequest::new();
            request.set_account("bank".to_string());
            request
        }))
        .unwrap();
    assert_eq!(response.get_balance(), 8_000_000_000_000_000_000);
}

/// Create a new random token address.
fn create_address() -> String {
    thread_rng().gen_ascii_chars().take(32).collect()
}

/// Runs the token scenario.
fn scenario(client: &mut token::Client, runtime: &mut Runtime) {
    // Generate random addresses.
    let destination = create_address();
    let poor = create_address();

    // Transfer some funds.
    runtime
        .block_on(client.transfer({
            let mut request = token::TransferRequest::new();
            request.set_sender("bank".to_string());
            request.set_destination(destination.clone());
            request.set_value(3);
            request
        }))
        .unwrap();
    measure_counter_inc!("value_transferred", 3);

    // Check balances.
    let response = runtime
        .block_on(client.get_balance({
            let mut request = token::GetBalanceRequest::new();
            request.set_account(destination.clone());
            request
        }))
        .unwrap();
    assert_eq!(response.get_balance(), 3);

    let response = runtime
        .block_on(client.get_balance({
            let mut request = token::GetBalanceRequest::new();
            request.set_account(poor.clone());
            request
        }))
        .unwrap();
    assert_eq!(response.get_balance(), 0);
}

/// Finalize the token scenario.
fn finalize(client: &mut token::Client, runs: usize, threads: usize, runtime: &mut Runtime) {
    // Check final balance.
    let response = runtime
        .block_on(client.get_balance({
            let mut request = token::GetBalanceRequest::new();
            request.set_account("bank".to_string());
            request
        }))
        .unwrap();
    assert_eq!(
        response.get_balance(),
        8_000_000_000_000_000_000 - 3 * runs as u64 * threads as u64
    );
}

#[cfg(feature = "benchmark")]
fn main() {
    let results = benchmark_client!(token, init, scenario, finalize);
    results.show();
}

#[cfg(not(feature = "benchmark"))]
fn main() {
    let mut runtime = Runtime::new().unwrap();
    let mut client = runtime_client!(token);
    init(&mut client, 1, 1, &mut runtime);
    scenario(&mut client, &mut runtime);
    finalize(&mut client, 1, 1, &mut runtime);
}
