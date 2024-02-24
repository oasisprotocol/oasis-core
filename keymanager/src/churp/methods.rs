//! CHURP methods exported to remote clients via enclave RPC.
use oasis_core_runtime::enclave_rpc::{
    dispatcher::{
        Handler as RpcHandler, Method as RpcMethod, MethodDescriptor as RpcMethodDescriptor,
    },
    types::Kind as RpcKind,
};

use crate::churp::Churp;

/// Name of the `init` method.
pub const METHOD_INIT: &str = "churp/init";

impl RpcHandler for Churp {
    fn methods(&'static self) -> Vec<RpcMethod> {
        vec![RpcMethod::new(
            RpcMethodDescriptor {
                name: METHOD_INIT.to_string(),
                kind: RpcKind::LocalQuery,
            },
            move |_ctx: &_, req: &_| self.init(req),
        )]
    }
}
