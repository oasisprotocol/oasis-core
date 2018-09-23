#[macro_use]
extern crate clap;
extern crate rand;

#[macro_use]
extern crate client_utils;
extern crate ekiden_contract_client;
extern crate ekiden_core;
extern crate ekiden_rpc_client;

extern crate token_api;

use clap::{App, Arg};

use ekiden_contract_client::create_contract_client;
use ekiden_core::futures::Future;
use token_api::with_api;

with_api! {
    create_contract_client!(token, token_api, api);
}

fn scenario_null(client: &mut token::Client) {
    client.null(true).wait().unwrap();
}

fn scenario_null_storage_insert_1(client: &mut token::Client) {
    client.null_storage_insert(1).wait().unwrap();
}

fn scenario_null_storage_insert_2(client: &mut token::Client) {
    client.null_storage_insert(2).wait().unwrap();
}

fn scenario_null_storage_insert_10(client: &mut token::Client) {
    client.null_storage_insert(10).wait().unwrap();
}

fn scenario_list_storage_insert(client: &mut token::Client) {
    client
        .list_storage_insert(vec![
            b"first item first item first item first item first item".to_vec(),
            b"second item second item second item second item second item".to_vec(),
            b"third item third item third item third item third item".to_vec(),
            b"fourth item fourth item fourth item fourth item fourth item".to_vec(),
            b"fifth item fifth item fifth item fifth item fifth item".to_vec(),
            b"sixth item sixth item sixth item sixth item sixth item".to_vec(),
        ])
        .wait()
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
