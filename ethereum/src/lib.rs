// ! Ekiden Ethereum backend components.
extern crate chrono;
#[macro_use]
extern crate clap;
extern crate constant_time_eq;
extern crate ekiden_beacon_base;
extern crate ekiden_common;
#[macro_use]
extern crate ekiden_di;
extern crate ekiden_epochtime;
extern crate ekiden_registry_base;
extern crate ekiden_registry_dummy;
extern crate ekiden_stake_base;
extern crate ekiden_storage_base;
extern crate ethabi;
extern crate rustc_hex;
extern crate secp256k1;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate serde_cbor;
extern crate tiny_keccak;
extern crate tokio_core;
extern crate web3;
#[macro_use]
extern crate log;

mod beacon;
mod contract_registry;
mod entity_registry;
pub mod identity;
mod mockepoch;
pub mod signature;
pub mod stake;
pub mod truffle;
pub mod web3_di;

pub use beacon::{EthereumRandomBeacon, EthereumRandomBeaconViaWebsocket};
pub use contract_registry::EthereumContractRegistryBackend;
pub use entity_registry::{EthereumEntityRegistryBackend, EthereumEntityRegistryViaWebsocket};
pub use mockepoch::{EthereumMockTime, EthereumMockTimeViaWebsocket};
pub use stake::{EthereumStake, EthereumStakeViaWebsocket};
