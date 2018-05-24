// Re-exports needed in exported macros.
pub extern crate grpcio;

pub extern crate ekiden_core;
pub extern crate ekiden_registry_base;
pub extern crate ekiden_registry_client;
pub extern crate ekiden_rpc_client;
pub extern crate ekiden_scheduler_base;
pub extern crate ekiden_scheduler_client;

#[macro_export]
macro_rules! default_app {
    () => {
        App::new(concat!(crate_name!(), " client"))
                            .about(crate_description!())
                            .author(crate_authors!())
                            .version(crate_version!())
                            // TODO: Change this once we handle backend configuration properly.
                            .arg(
                                Arg::with_name("dummy-host")
                                    .long("dummy-host")
                                    .help("Shared dummy node host")
                                    .takes_value(true)
                                    .default_value("127.0.0.1"),
                            )
                            // TODO: Change this once we handle backend configuration properly.
                            .arg(
                                Arg::with_name("dummy-port")
                                    .long("dummy-port")
                                    .help("Shared dummy node port")
                                    .takes_value(true)
                                    .default_value("42261"),
                            )
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
        use std::sync::Arc;

        use $crate::macros::ekiden_core::bytes::B256;
        use $crate::macros::ekiden_registry_base::EntityRegistryBackend;
        use $crate::macros::ekiden_registry_client::EntityRegistryClient;
        use $crate::macros::ekiden_rpc_client::backend::Web3RpcClientBackend;
        use $crate::macros::ekiden_scheduler_base::{CommitteeType, Role, Scheduler};
        use $crate::macros::ekiden_scheduler_client::SchedulerClient;
        use $crate::macros::grpcio;

        // Create gRPC event loop.
        let grpc_environment = Arc::new(grpcio::EnvBuilder::new().build());

        // Perform computation group leader discovery.
        // TODO: Change this once we handle backend configuration properly.
        let channel = grpcio::ChannelBuilder::new(grpc_environment.clone()).connect(&format!(
            "{}:{}",
            $args.value_of("dummy-host").unwrap(),
            value_t!($args, "dummy-port", u16).unwrap(),
        ));
        let scheduler = SchedulerClient::new(channel.clone());
        let entity_registry = EntityRegistryClient::new(channel.clone());

        // Get computation group leader node.
        let contract_id = value_t!($args, "mr-enclave", B256).unwrap_or_else(|e| e.exit());
        let committees = scheduler
            .get_committees(contract_id)
            .wait()
            .expect("failed to fetch committees from scheduler");
        let committee = committees
            .iter()
            .filter(|committee| committee.kind == CommitteeType::Compute)
            .next()
            .expect("missing compute committee");
        let leader = committee
            .members
            .iter()
            .filter(|member| member.role == Role::Leader)
            .next()
            .expect("missing compute committee leader");

        // Resolve leader node based on its public key.
        let node = entity_registry
            .get_node(leader.public_key)
            .wait()
            .expect("failed to resolve leader node");
        let address = node.addresses.first().expect("no address for leader node");

        Web3RpcClientBackend::new(
            grpc_environment,
            &format!("{}", address.ip()),
            address.port(),
        ).unwrap()
    }};
}

#[macro_export]
macro_rules! contract_client {
    ($signer:ident, $contract:ident, $args:ident, $backend:ident) => {{
        use std::sync::Arc;

        use $crate::macros::ekiden_core::enclave::quote::MrEnclave;

        $contract::Client::new(
            Arc::new($backend),
            value_t!($args, "mr-enclave", MrEnclave).unwrap_or_else(|e| e.exit()),
            $signer,
        )
    }};
    ($signer:ident, $contract:ident, $args:ident) => {{
        let backend = default_backend!($args);
        contract_client!($signer, $contract, $args, backend)
    }};
    ($signer:ident, $contract:ident) => {{
        let args = default_app!().get_matches();
        contract_client!($signer, $contract, args)
    }};
}

#[cfg(feature = "benchmark")]
#[macro_export]
macro_rules! benchmark_client {
    ($signer:ident, $contract:ident, $init:expr, $scenario:expr, $finalize:expr) => {{
        let args = std::sync::Arc::new(
            default_app!()
                .arg(
                    Arg::with_name("benchmark-threads")
                        .long("benchmark-threads")
                        .help("Number of benchmark threads")
                        .takes_value(true)
                        .default_value("4"),
                )
                .arg(
                    Arg::with_name("benchmark-runs")
                        .long("benchmark-runs")
                        .help("Number of scenario runs")
                        .takes_value(true)
                        .default_value("1000"),
                )
                .get_matches(),
        );

        let benchmark = $crate::benchmark::Benchmark::new(
            value_t!(args, "benchmark-runs", usize).unwrap_or_else(|e| e.exit()),
            value_t!(args, "benchmark-threads", usize).unwrap_or_else(|e| e.exit()),
            move || {
                let args = args.clone();
                contract_client!($signer, $contract, args)
            },
        );

        benchmark.run($init, $scenario, $finalize)
    }};
}
