//! Misc Macros used across Ekiden.

/// Close out a gRPC service call with a given error
#[macro_export]
macro_rules! invalid_rpc {
    ($sink:ident, $code:ident, $e:expr) => {
        $sink.fail(::grpcio::RpcStatus::new($code, Some(format!("{:?}", $e))))
    };
}

/// Report an error and cause the application to abort immediately.
#[macro_export]
macro_rules! crash {
    ($($arg:tt)*) => {
        error!($($arg)*);
        ::std::process::exit(1);
    }
}
