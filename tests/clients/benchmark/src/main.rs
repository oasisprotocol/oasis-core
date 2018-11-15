#[macro_use]
extern crate clap;
extern crate rand;

#[macro_use]
extern crate client_utils;
extern crate ekiden_core;
extern crate ekiden_rpc_client;
extern crate ekiden_runtime_client;

extern crate token_api;

use clap::{App, Arg};

use ekiden_core::tokio::runtime::current_thread::Runtime;
use ekiden_runtime_client::create_runtime_client;
use token_api::with_api;

with_api! {
    create_runtime_client!(token, token_api, api);
}

fn scenario_null(client: &mut token::Client, runtime: &mut Runtime) {
    runtime.block_on(client.null(true.into())).unwrap();
}

fn scenario_null_storage_insert_1(client: &mut token::Client, runtime: &mut Runtime) {
    runtime
        .block_on(client.null_storage_insert(1.into()))
        .unwrap();
}

fn scenario_null_storage_insert_2(client: &mut token::Client, runtime: &mut Runtime) {
    runtime
        .block_on(client.null_storage_insert(2.into()))
        .unwrap();
}

fn scenario_null_storage_insert_10(client: &mut token::Client, runtime: &mut Runtime) {
    runtime
        .block_on(client.null_storage_insert(10.into()))
        .unwrap();
}

fn scenario_list_storage_insert(client: &mut token::Client, runtime: &mut Runtime) {
    runtime
        .block_on(
            client.list_storage_insert(
                vec![
                    b"first item first item first item first item first item".to_vec(),
                    b"second item second item second item second item second item".to_vec(),
                    b"third item third item third item third item third item".to_vec(),
                    b"fourth item fourth item fourth item fourth item fourth item".to_vec(),
                    b"fifth item fifth item fifth item fifth item fifth item".to_vec(),
                    b"sixth item sixth item sixth item sixth item sixth item".to_vec(),
                ].into(),
            ),
        )
        .unwrap();
}

fn main() {
    let app = benchmark_app!();

    benchmark_multiple!(
        app,
        token,
        [
            scenario_null,
            scenario_null_storage_insert_1,
            scenario_null_storage_insert_2,
            scenario_null_storage_insert_10,
            scenario_list_storage_insert
        ]
    );
}
