use std::sync::Arc;

use grpcio;

use ekiden_core::environment::Environment;
use ekiden_di::create_component;

/// Compute node environment.
pub struct ComputeNodeEnvironment {
    /// gRPC environment.
    grpc_environment: Arc<grpcio::Environment>,
}

impl ComputeNodeEnvironment {
    pub fn new(grpc_environment: grpcio::Environment) -> Self {
        Self {
            grpc_environment: Arc::new(grpc_environment),
        }
    }
}

impl Environment for ComputeNodeEnvironment {
    fn grpc(&self) -> Arc<grpcio::Environment> {
        self.grpc_environment.clone()
    }
}

// Register for dependency injection.
create_component!(
    compute_node,
    "environment",
    ComputeNodeEnvironment,
    Environment,
    (|container: &mut Container| -> Result<Box<Any>> {
        let args = container.get_arguments().unwrap();
        let grpc_environment =
            grpcio::Environment::new(value_t_or_exit!(args, "grpc-threads", usize));

        let instance: Arc<Environment> = Arc::new(ComputeNodeEnvironment::new(grpc_environment));
        Ok(Box::new(instance))
    }),
    [Arg::with_name("grpc-threads")
        .long("grpc-threads")
        .help("Number of threads to use for the event loop")
        .default_value("4")
        .takes_value(true)]
);
