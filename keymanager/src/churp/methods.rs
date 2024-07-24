//! CHURP methods exported to remote clients via enclave RPC.
use oasis_core_runtime::enclave_rpc::{
    dispatcher::{
        Handler as RpcHandler, Method as RpcMethod, MethodDescriptor as RpcMethodDescriptor,
    },
    types::Kind as RpcKind,
};

use crate::churp::{Churp, Handler};

/// Name of the `apply` method.
pub const METHOD_APPLY: &str = "churp/apply";
/// Name of the `share_reduction` method.
pub const METHOD_SHARE_REDUCTION: &str = "churp/share_reduction";
/// Name of the `share_distribution` method.
pub const METHOD_SHARE_DISTRIBUTION: &str = "churp/share_distribution";
/// Name of the `proactivization` method.
pub const METHOD_PROACTIVIZATION: &str = "churp/proactivization";
/// Name of the `confirm` method.
pub const METHOD_CONFIRM: &str = "churp/confirm";
/// Name of the `finalize` method.
pub const METHOD_FINALIZE: &str = "churp/finalize";
/// Name of the `verification_matrix` method.
pub const METHOD_VERIFICATION_MATRIX: &str = "churp/verification_matrix";
/// Name of the `share_reduction_point` method.
pub const METHOD_SHARE_REDUCTION_POINT: &str = "churp/share_reduction_point";
/// Name of the `share_distribution_point` method.
pub const METHOD_SHARE_DISTRIBUTION_POINT: &str = "churp/share_distribution_point";
/// Name of the `bivariate_share` method.
pub const METHOD_BIVARIATE_SHARE: &str = "churp/bivariate_share";
/// Name of the `sgx_policy_key_share` method.
pub const METHOD_SGX_POLICY_KEY_SHARE: &str = "churp/sgx_policy_key_share";

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
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_SGX_POLICY_KEY_SHARE.to_string(),
                    kind: RpcKind::NoiseSession,
                },
                move |ctx: &_, req: &_| self.sgx_policy_key_share(ctx, req),
            ),
            /* Local queries */
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_APPLY.to_string(),
                    kind: RpcKind::LocalQuery,
                },
                move |_ctx: &_, req: &_| self.apply(req),
            ),
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_SHARE_REDUCTION.to_string(),
                    kind: RpcKind::LocalQuery,
                },
                move |_ctx: &_, req: &_| self.share_reduction(req),
            ),
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_SHARE_DISTRIBUTION.to_string(),
                    kind: RpcKind::LocalQuery,
                },
                move |_ctx: &_, req: &_| self.share_distribution(req),
            ),
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_PROACTIVIZATION.to_string(),
                    kind: RpcKind::LocalQuery,
                },
                move |_ctx: &_, req: &_| self.proactivization(req),
            ),
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_CONFIRM.to_string(),
                    kind: RpcKind::LocalQuery,
                },
                move |_ctx: &_, req: &_| self.confirmation(req),
            ),
            RpcMethod::new(
                RpcMethodDescriptor {
                    name: METHOD_FINALIZE.to_string(),
                    kind: RpcKind::LocalQuery,
                },
                move |_ctx: &_, req: &_| self.finalize(req),
            ),
        ]
    }
}
