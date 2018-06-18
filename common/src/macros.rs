//! Misc Macros used across Ekiden.

/// Close out a gRPC service call with a given error
#[macro_export]
macro_rules! invalid_rpc {
    ($sink:ident, $code:ident, $e:expr) => {
        $sink.fail(::grpcio::RpcStatus::new($code, Some(format!("{:?}", $e))))
    };
}
