use clap::value_t;

/// Dependency used for injecting `--node-address` command line argument when
/// using create_component() macro.
pub struct RemoteNodeInfo {
    // Remote node address.
    node_address: String,
}

pub trait RemoteNode: Sync + Send {
    /// Return remote node address.
    fn get_node_address(&self) -> &str;
}

impl RemoteNode for RemoteNodeInfo {
    fn get_node_address(&self) -> &str {
        self.node_address.as_str()
    }
}

// Register for dependency injection.
create_component!(
    remote_node,
    "remote-node",
    RemoteNodeInfo,
    RemoteNode,
    (|container: &mut Container| -> Result<Box<Any>> {
        let args = container.get_arguments().unwrap();

        let rnode: Arc<RemoteNode> = Arc::new(RemoteNodeInfo {
            node_address: value_t!(args.value_of("node-address"), String)
                .unwrap_or_else(|e| e.exit()),
        });

        Ok(Box::new(rnode))
    }),
    [Arg::with_name("node-address")
        .long("node-address")
        .help("Remote node hostname:port that the client should connect to")
        .takes_value(true)
        .default_value("127.0.0.1:42261")]
);
