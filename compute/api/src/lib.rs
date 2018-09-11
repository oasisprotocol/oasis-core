extern crate futures;
extern crate grpcio;
extern crate protobuf;

extern crate ekiden_roothash_api;

mod generated;

use ekiden_roothash_api as roothash;

pub use generated::computation_group::*;
pub use generated::computation_group_grpc::*;
pub use generated::contract::*;
pub use generated::contract_grpc::*;
