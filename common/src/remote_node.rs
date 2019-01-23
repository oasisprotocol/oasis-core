use std::sync::Arc;

use clap::{value_t, Arg, ArgMatches};
use grpcio::{Channel, ChannelBuilder};

use crate::environment::Environment;

/// Common remote node connection parameters.
pub struct RemoteNode {
    // Remote node address.
    node_address: String,
}

impl RemoteNode {
    /// Create a new instance from argument matches.
    pub fn from_args(matches: &ArgMatches) -> Self {
        Self {
            node_address: value_t!(matches.value_of("node-address"), String)
                .unwrap_or_else(|e| e.exit()),
        }
    }

    /// Return remote node address.
    pub fn get_node_address(&self) -> &str {
        self.node_address.as_str()
    }

    /// Create a new gRPC channel to the remote node.
    pub fn create_channel(&self, environment: Arc<Environment>) -> Channel {
        ChannelBuilder::new(environment.grpc())
            .max_receive_message_len(i32::max_value())
            .max_send_message_len(i32::max_value())
            .connect(self.get_node_address())
    }
}

/// Create a Vec of args for App::args(&...) with configuration options for the remote node.
pub fn get_arguments<'a, 'b>() -> Vec<Arg<'a, 'b>> {
    vec![
        Arg::with_name("node-address")
            .long("node-address")
            .help("Remote node hostname:port that the client should connect to")
            .takes_value(true)
            .default_value("127.0.0.1:42261"),
    ]
}
