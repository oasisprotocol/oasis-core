extern crate futures;
extern crate grpcio;
extern crate protobuf;

extern crate ekiden_common_api;

mod generated;

use ekiden_common_api as common;

pub use generated::entity::*;
pub use generated::entity_grpc::*;
