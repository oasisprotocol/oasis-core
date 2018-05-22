// ! Ekidem Ethereum random beacon backend.
extern crate chrono;
extern crate ekiden_beacon_base;
extern crate ekiden_common;
extern crate ethabi;
extern crate serde_json;
extern crate web3;
#[macro_use]
extern crate log;

mod backend;

pub use backend::EthereumRandomBeacon;
