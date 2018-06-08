// ! Ekiden Ethereum backend components.
extern crate chrono;
extern crate ekiden_beacon_base;
extern crate ekiden_common;
extern crate ethabi;
extern crate rustc_hex;
extern crate serde_json;
extern crate web3;
#[macro_use]
extern crate log;

mod beacon;
mod mockepoch;
pub mod truffle;

pub use beacon::EthereumRandomBeacon;
pub use mockepoch::EthereumMockTime;
