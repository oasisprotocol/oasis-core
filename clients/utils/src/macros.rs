#[macro_export]
macro_rules! default_app {
    () => {
        App::new(concat!(crate_name!(), " client"))
            .about(crate_description!())
            .author(crate_authors!())
            .version(crate_version!())
            .arg(Arg::with_name("host")
                 .long("host")
                 .short("h")
                 .takes_value(true)
                 .default_value("127.0.0.1")
                 .display_order(1))
            .arg(Arg::with_name("port")
                 .long("port")
                 .short("p")
                 .takes_value(true)
                 .default_value("9001")
                 .display_order(2))
            .arg(Arg::with_name("nodes")
                .long("nodes")
                .help("A list of comma-separated compute node addresses (e.g. host1:9001,host2:9004)")
                .takes_value(true))
            .arg(Arg::with_name("mr-enclave")
                 .long("mr-enclave")
                 .value_name("MRENCLAVE")
                 .help("MRENCLAVE in hex format")
                 .takes_value(true)
                 .required(true)
                 .display_order(3))
    };
}

#[macro_export]
macro_rules! default_backend {
    ($args:ident) => {{
        // Create reactor (event loop) in a separate thread.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut reactor = tokio_core::reactor::Core::new().unwrap();
            tx.send(reactor.remote()).unwrap();
            reactor.run(futures::empty::<(), ()>()).unwrap();
        });

        let remote = rx.recv().unwrap();

        if $args.is_present("nodes") {
            // Pool of compute nodes.
            use std::str::FromStr;
            use ekiden_rpc_client::backend::web3::ComputeNodeAddress;

            let nodes: Vec<ComputeNodeAddress> = $args
                .value_of("nodes")
                .unwrap()
                .split(",")
                .map(|address: &str| {
                    let parts: Vec<&str> = address.split(":").collect();

                    ComputeNodeAddress {
                        host: parts[0].to_string(),
                        port: u16::from_str(&parts[1]).unwrap(),
                    }
                })
                .collect();

            ekiden_rpc_client::backend::Web3ContractClientBackend::new_pool(
                remote,
                &nodes
            ).unwrap()
        } else {
            ekiden_rpc_client::backend::Web3ContractClientBackend::new(
                remote,
                $args.value_of("host").unwrap(),
                value_t!($args, "port", u16).unwrap_or(9001)
            ).unwrap()
        }
    }};
}

#[macro_export]
macro_rules! contract_client {
    ($contract:ident, $args:ident, $backend:ident) => {
        $contract::Client::new(
            $backend,
            value_t!($args, "mr-enclave", ekiden_core::enclave::quote::MrEnclave).unwrap_or_else(|e| e.exit())
        )
    };
    ($contract:ident, $args:ident) => {
        {
            let backend = default_backend!($args);
            contract_client!($contract, $args, backend)
        }
    };
    ($contract:ident) => {
        {
            let args = default_app!().get_matches();
            contract_client!($contract, args)
        }
    };
}

#[cfg(feature = "benchmark")]
#[macro_export]
macro_rules! benchmark_client {
    ($contract:ident, $init:expr, $scenario:expr, $finalize:expr) => {{
        let args = std::sync::Arc::new(
            default_app!()
                .arg(Arg::with_name("benchmark-threads")
                    .long("benchmark-threads")
                    .help("Number of benchmark threads")
                    .takes_value(true)
                    .default_value("4"))
                .arg(Arg::with_name("benchmark-runs")
                    .long("benchmark-runs")
                    .help("Number of scenario runs")
                    .takes_value(true)
                    .default_value("1000"))
            .get_matches()
        );

        let benchmark = $crate::benchmark::Benchmark::new(
            value_t!(args, "benchmark-runs", usize).unwrap_or_else(|e| e.exit()),
            value_t!(args, "benchmark-threads", usize).unwrap_or_else(|e| e.exit()),
            move || {
                let args = args.clone();
                contract_client!($contract, args)
            }
        );

        benchmark.run($init, $scenario, $finalize)
    }}
}
