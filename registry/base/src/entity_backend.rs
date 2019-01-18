//! Registry backend interface.
use std::sync::Arc;

use grpcio;

use ekiden_common::environment::Environment;
use ekiden_common::address::Address;
use ekiden_common::bytes::B256;
use ekiden_common::futures::BoxFuture;
use ekiden_common::x509::{Certificate, CERTIFICATE_COMMON_NAME};

/// Registry backend implementing the Ekiden registry interface.
pub trait EntityRegistryBackend: Send + Sync {
    /// Get a registered node's transport information.
    fn get_node_transport(&self, id: B256) -> BoxFuture<NodeTransport>;
}

// Node transport information.
pub struct NodeTransport {
    /// The list of `Address`es at which the node can be reached.
    pub addresses: Vec<Address>,
    /// Certificate for establishing TLS connections.
    pub certificate: Certificate,
}

impl NodeTransport {
    /// Construct a gRPC channel to given node.
    pub fn connect(&self, environment: Arc<Environment>) -> grpcio::Channel {
        grpcio::ChannelBuilder::new(environment.grpc())
            .override_ssl_target(CERTIFICATE_COMMON_NAME)
            .secure_connect(
                // TODO: Configure all addresses instead of just the first one.
                &format!("{}", self.addresses[0]),
                grpcio::ChannelCredentialsBuilder::new()
                    .root_cert(self.certificate.get_pem().unwrap())
                    .build(),
            )
    }
}
