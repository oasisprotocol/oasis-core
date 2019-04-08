//! Connection to the Ekiden node.
use std::sync::Arc;

use grpcio::{Channel, ChannelBuilder, Environment};

/// An Ekiden node connection.
pub struct Node {
    channel: Channel,
}

impl Node {
    /// Create a new Ekiden node connection.
    pub fn new(environment: Arc<Environment>, address: &str) -> Self {
        // Create a gRPC channel with the Ekiden node.
        let channel = ChannelBuilder::new(environment)
            .max_receive_message_len(i32::max_value())
            .max_send_message_len(i32::max_value())
            .connect(address);

        Self { channel }
    }

    /// gRPC channel to Ekiden node.
    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }
}
