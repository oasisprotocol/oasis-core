//! Ekiden environment.
use std::env;
use std::sync::{Arc, Mutex};

use clap::value_t_or_exit;
use grpcio;

use super::futures::{Executor, Future, GrpcExecutor};

/// Ekiden application environment.
///
/// Currently provides things like the used event loop.
pub trait Environment: Sync + Send {
    /// Get the gRPC environment.
    fn grpc(&self) -> Arc<grpcio::Environment>;

    /// Spawn a task onto the environment's executor.
    fn spawn(&self, f: Box<Future<Item = (), Error = ()> + Send>);
}

/// gRPC-based application environment.
pub struct GrpcEnvironment {
    /// gRPC environment.
    grpc_environment: Arc<grpcio::Environment>,
    /// gRPC executor.
    grpc_executor: Mutex<GrpcExecutor>,
}

impl GrpcEnvironment {
    pub fn new(grpc_environment: grpcio::Environment) -> Self {
        // Enable support for ECDSA-based ciphers in gRPC.
        env::set_var("GRPC_SSL_CIPHER_SUITES", "ECDHE-ECDSA-AES256-GCM-SHA384");

        let grpc_environment = Arc::new(grpc_environment);

        Self {
            grpc_environment: grpc_environment.clone(),
            grpc_executor: Mutex::new(GrpcExecutor::new(grpc_environment)),
        }
    }
}

impl Environment for GrpcEnvironment {
    fn grpc(&self) -> Arc<grpcio::Environment> {
        self.grpc_environment.clone()
    }

    fn spawn(&self, f: Box<Future<Item = (), Error = ()> + Send>) {
        let mut executor = self.grpc_executor.lock().unwrap();
        executor.spawn(f);
    }
}

// Register for dependency injection.
create_component!(
    grpc,
    "environment",
    GrpcEnvironment,
    Environment,
    (|container: &mut Container| -> Result<Box<Any>> {
        let args = container.get_arguments().unwrap();
        let grpc_environment =
            grpcio::Environment::new(value_t_or_exit!(args, "grpc-threads", usize));

        let instance: Arc<Environment> = Arc::new(GrpcEnvironment::new(grpc_environment));
        Ok(Box::new(instance))
    }),
    [Arg::with_name("grpc-threads")
        .long("grpc-threads")
        .help("Number of threads to use for the event loop")
        .default_value("4")
        .takes_value(true)]
);
