extern crate futures;
extern crate grpcio;
extern crate protobuf;
extern crate ekiden_common_api;

use ekiden_common_api as common;

mod generated;

pub use generated::scheduler::*;
pub use generated::scheduler_grpc::*;
