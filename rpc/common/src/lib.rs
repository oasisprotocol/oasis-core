extern crate byteorder;
extern crate protobuf;
extern crate serde;
extern crate sodalite;

#[macro_use]
extern crate ekiden_common;
extern crate ekiden_enclave_common;

pub mod reflection;
pub mod secure_channel;
pub mod client;

mod generated;

#[macro_use]
mod macros;

mod protocol;

pub mod api {
    pub use generated::enclave_rpc::*;
    pub use protocol::*;
}
