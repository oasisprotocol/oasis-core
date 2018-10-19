extern crate ekiden_common_api;
extern crate ekiden_registry_api;
extern crate futures;
extern crate grpcio;
extern crate protobuf;

use ekiden_registry_api as registry;
// Compiled code tries to access `runtime` package instead of `registry` package.
// https://github.com/oasislabs/ekiden/issues/1083
use registry as runtime;

mod generated;

pub use generated::scheduler::*;
pub use generated::scheduler_grpc::*;
