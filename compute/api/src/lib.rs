extern crate futures;
extern crate grpcio;
extern crate protobuf;

extern crate ekiden_common_api;

mod generated;

use ekiden_common_api as common;

pub use generated::computation_group::*;
pub use generated::computation_group_grpc::*;
pub use generated::contract::*;
pub use generated::contract_grpc::*;
