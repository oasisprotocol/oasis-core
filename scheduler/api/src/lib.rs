extern crate ekiden_common_api;
extern crate futures;
extern crate grpcio;
extern crate protobuf;

use ekiden_common_api as common;

mod generated;

pub use generated::scheduler::*;
pub use generated::scheduler_grpc::*;
