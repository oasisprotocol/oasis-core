//! Client for service defined in go/control/api.
use grpcio::{CallOption, Channel, Client, ClientUnaryReceiver, Result};

grpc_method!(
    METHOD_REQUEST_SHUTDOWN,
    "/oasis-core.NodeController/RequestShutdown",
    bool,
    ()
);
grpc_method!(
    METHOD_WAIT_SYNC,
    "/oasis-core.NodeController/WaitSync",
    (),
    ()
);
grpc_method!(
    METHOD_IS_SYNCED,
    "/oasis-core.NodeController/IsSynced",
    (),
    bool
);

/// A node controller gRPC service client.
#[derive(Clone)]
pub struct NodeControllerClient {
    client: Client,
}

impl NodeControllerClient {
    /// Create a new node controller client.
    pub fn new(channel: Channel) -> Self {
        NodeControllerClient {
            client: Client::new(channel),
        }
    }

    /// Request the node to shut down gracefully.
    pub fn request_shutdown(&self, wait: bool, opt: CallOption) -> Result<ClientUnaryReceiver<()>> {
        self.client
            .unary_call_async(&METHOD_REQUEST_SHUTDOWN, &wait, opt)
    }

    /// Wait for the node to finish syncing.
    pub fn wait_sync(&self, opt: CallOption) -> Result<ClientUnaryReceiver<()>> {
        self.client.unary_call_async(&METHOD_WAIT_SYNC, &(), opt)
    }

    /// Check whether the node has finished syncing.
    pub fn is_synced(&self, opt: CallOption) -> Result<ClientUnaryReceiver<bool>> {
        self.client.unary_call_async(&METHOD_IS_SYNCED, &(), opt)
    }
}
