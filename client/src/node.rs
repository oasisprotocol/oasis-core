//! Connection to an Oasis node.
use std::sync::Arc;

use grpcio::{Channel, ChannelBuilder, Environment};

/// An Oasis node connection.
pub struct Node {
    channel: Channel,
}

impl Node {
    /// Create a new Oasis node connection.
    pub fn new(environment: Arc<Environment>, address: &str) -> Self {
        // Create a gRPC channel with the Oasis node.
        let channel = ChannelBuilder::new(environment)
            .max_receive_message_len(i32::max_value())
            .max_send_message_len(i32::max_value())
            .connect(address);

        Self { channel }
    }

    /// gRPC channel to Oasis node.
    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }
}
