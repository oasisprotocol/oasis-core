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
/// Name of the `verification_matrix` method.
pub const METHOD_VERIFICATION_MATRIX: &str = "churp/verification_matrix";
/// Name of the `share_reduction_point` method.
pub const METHOD_SHARE_REDUCTION_POINT: &str = "churp/share_reduction_point";
/// Name of the `share_distribution_point` method.
pub const METHOD_SHARE_DISTRIBUTION_POINT: &str = "churp/share_distribution_point";
/// Name of the `bivariate_share` method.
pub const METHOD_BIVARIATE_SHARE: &str = "churp/bivariate_share";

impl RpcHandler for Churp {
    fn methods(&'static self) -> Vec<RpcMethod> {
        vec![
            /* Insecure queries */
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_VERIFICATION_MATRIX.to_string(),
                    kind: RpcKind::InsecureQuery,
                },
                move |_ctx: &_, req: &_| self.verification_matrix(req),
            ),
            /* Noise sessions */
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_SHARE_REDUCTION_POINT.to_string(),
                    kind: RpcKind::NoiseSession,
                },
                move |ctx: &_, req: &_| self.share_reduction_switch_point(ctx, req),
            ),
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_SHARE_DISTRIBUTION_POINT.to_string(),
                    kind: RpcKind::NoiseSession,
                },
                move |ctx: &_, req: &_| self.share_distribution_switch_point(ctx, req),
            ),
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_BIVARIATE_SHARE.to_string(),
                    kind: RpcKind::NoiseSession,
                },
                move |ctx: &_, req: &_| self.bivariate_share(ctx, req),
            ),
            /* Local queries */
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_INIT.to_string(),
                    kind: RpcKind::LocalQuery,
                },
                move |_ctx: &_, req: &_| self.init(req),
            ),
        ]
    }
}
