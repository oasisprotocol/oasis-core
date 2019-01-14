use clap::value_t;

/// Dependency used for injecting `--node-host` and `--node-port` command line arguments when
/// using create_component() macro.
pub struct RemoteNodeInfo {
    // Remote node host.
    node_host: String,
    // Remote node port.
    node_port: u16,
}

pub trait RemoteNode: Sync + Send {
    /// Return remote node host.
    fn get_node_host(&self) -> &str;

    /// Return remote node port.
    fn get_node_port(&self) -> u16;
}

impl RemoteNode for RemoteNodeInfo {
    fn get_node_host(&self) -> &str {
        self.node_host.as_str()
    }

    fn get_node_port(&self) -> u16 {
        self.node_port
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
            node_host: value_t!(args.value_of("node-host"), String).unwrap_or_else(|e| e.exit()),
            node_port: value_t!(args.value_of("node-port"), u16).unwrap_or_else(|e| e.exit()),
        });

        Ok(Box::new(rnode))
    }),
    [
        Arg::with_name("node-host")
            .long("node-host")
            .help("Remote node hostname that the client should connect to")
            .takes_value(true)
            .default_value("127.0.0.1"),
        Arg::with_name("node-port")
            .long("node-port")
            .help("Remote node port that the client should connect to")
            .takes_value(true)
            .default_value("42261")
    ]
);
