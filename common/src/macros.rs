//! Misc Macros used across Ekiden.

/// Close out a gRPC service call with a given error.
#[macro_export]
macro_rules! invalid_rpc {
    ($sink:ident, $code:ident, $e:expr) => {
        $sink.fail(::grpcio::RpcStatus::new($code, Some(format!("{:?}", $e))))
    };
}

/// Handle a gRPC service call.
#[macro_export]
macro_rules! handle_rpc {
    ($ctx:ident, $sink:ident, $handler:block, $response:expr) => {
        let handler = || -> $crate::error::Result<_> { $handler };
        let response = match handler() {
            Ok(()) => $sink.success($response),
            Err(error) => $sink.fail(RpcStatus::new(
                ::grpcio::RpcStatusCode::Internal,
                Some(error.description().to_owned()),
            )),
        };
        $ctx.spawn(response.map_err(|_error| ()));
    };
}
