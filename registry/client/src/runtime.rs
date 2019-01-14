//! Runtime registry gRPC client.
use std::convert::TryFrom;
use std::error::Error as StdError;
use std::sync::Arc;

use grpcio::{Channel, ChannelBuilder};

use ekiden_common::bytes::B256;
use ekiden_common::environment::Environment;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, stream, BoxFuture, BoxStream, Future, Stream};
use ekiden_common::identity::NodeIdentity;
use ekiden_common::node::Node;
use ekiden_common::remote_node::RemoteNode;
use ekiden_common::signature::Signed;
use ekiden_registry_api as api;
use ekiden_registry_base::runtime::Runtime;
use ekiden_registry_base::RuntimeRegistryBackend;

/// Scheduler client implements the Scheduler interface.
pub struct RuntimeRegistryClient(api::RuntimeRegistryClient);

impl RuntimeRegistryClient {
    pub fn new(channel: Channel) -> Self {
        RuntimeRegistryClient(api::RuntimeRegistryClient::new(channel))
    }

    pub fn from_node(
        node: &Node,
        environment: Arc<Environment>,
        identity: Arc<NodeIdentity>,
    ) -> Self {
        RuntimeRegistryClient::new(node.connect(environment, identity))
    }
}

impl RuntimeRegistryBackend for RuntimeRegistryClient {
    fn register_runtime(&self, runtime: Signed<Runtime>) -> BoxFuture<()> {
        let mut request = api::RegisterRuntimeRequest::new();
        request.set_runtime(runtime.into());
        match self.0.register_runtime_async(&request) {
            Ok(f) => Box::new(
                f.map(|_response| ())
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn get_runtime(&self, id: B256) -> BoxFuture<Runtime> {
        let mut request = api::RuntimeRequest::new();
        request.set_id(id.to_vec());
        match self.0.get_runtime_async(&request) {
            Ok(f) => Box::new(
                f.map_err(|error| Error::new(error.description()))
                    .and_then(|mut response| Ok(Runtime::try_from(response.take_runtime())?)),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn watch_runtimes(&self) -> BoxStream<Runtime> {
        let request = api::WatchRuntimesRequest::new();
        match self.0.watch_runtimes(&request) {
            Ok(s) => Box::new(s.then(|result| match result {
                Ok(response) => Ok(Runtime::try_from(response.get_runtime().to_owned())?),
                Err(error) => Err(Error::new(error.description())),
            })),
            Err(error) => Box::new(stream::once::<Runtime, _>(Err(Error::new(
                error.description(),
            )))),
        }
    }
}

// Register for dependency injection.
create_component!(
    remote,
    "runtime-registry-backend",
    RuntimeRegistryClient,
    RuntimeRegistryBackend,
    (|container: &mut Container| -> Result<Box<Any>> {
        let environment: Arc<Environment> = container.inject()?;

        // "node-host" and "node-port" arguments.
        let remote_node: Arc<RemoteNode> = container.inject()?;

        let channel = ChannelBuilder::new(environment.grpc()).connect(&format!(
            "{}:{}",
            remote_node.get_node_host(),
            remote_node.get_node_port(),
        ));

        let instance: Arc<RuntimeRegistryBackend> = Arc::new(RuntimeRegistryClient::new(channel));
        Ok(Box::new(instance))
    }),
    []
);
