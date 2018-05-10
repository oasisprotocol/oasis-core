extern crate ekiden_common_api;
extern crate futures;
extern crate grpcio;
extern crate protobuf;

mod generated;

use ekiden_common_api as common;

pub use generated::consensus::*;
pub use generated::consensus_grpc::*;
