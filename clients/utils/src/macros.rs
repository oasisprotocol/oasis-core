// Re-exports needed in exported macros.
pub use log::LevelFilter;
pub use pretty_env_logger::formatted_builder;

pub use ekiden_core::enclave::quote::MrEnclave;

#[macro_export]
macro_rules! default_app {
    () => {{
        use $crate::macros::LevelFilter;

        // Initialize logger.
        $crate::macros::formatted_builder()
            .unwrap()
            .filter(None, LevelFilter::Trace)
            .filter(Some("mio"), LevelFilter::Warn)
            .filter(Some("tokio_threadpool"), LevelFilter::Warn)
            .filter(Some("tokio_reactor"), LevelFilter::Warn)
            .init();

        App::new(concat!(crate_name!(), " client"))
            .about(crate_description!())
            .author(crate_authors!())
            .version(crate_version!())
            .arg(
                Arg::with_name("test-contract-id")
                    .long("test-contract-id")
                    .help("TEST ONLY OPTION: override contract identifier")
                    .takes_value(true)
                    .hidden(true),
            )
            .arg(
                Arg::with_name("mr-enclave")
                    .long("mr-enclave")
                    .value_name("MRENCLAVE")
                    .help("MRENCLAVE in hex format")
                    .takes_value(true)
                    .required(true)
                    .display_order(3),
            )
            .arg(
                Arg::with_name("rpc-timeout")
                    .long("rpc-timeout")
                    .value_name("RPC_TIMEOUT")
                    .help("Mark nodes that take longer than this many seconds as failed")
                    .takes_value(true),
            )
    }};
}

#[macro_export]
macro_rules! contract_client {
    ($signer:ident, $contract:ident, $args:ident, $container:ident) => {{
        use $crate::macros::*;

        // Determine contract identifier.
        let contract_id = if $args.is_present("test-contract-id") {
            value_t_or_exit!($args, "test-contract-id", B256)
        } else {
            value_t_or_exit!($args, "mr-enclave", B256)
        };

        $contract::Client::new(
            contract_id,
            value_t_or_exit!($args, "mr-enclave", MrEnclave),
            if $args.is_present("rpc-timeout") {
                Some(std::time::Duration::new(
                    value_t_or_exit!($args, "rpc-timeout", u64),
                    0,
                ))
            } else {
                None
            },
            $container.inject().unwrap(),
            $container.inject().unwrap(),
            $container.inject().unwrap(),
            $signer,
            $container.inject().unwrap(),
            $container.inject().unwrap(),
        )
    }};
    ($signer:ident, $contract:ident) => {{
        let known_components = $crate::components::create_known_components();
        let args = default_app!()
            .args(&known_components.get_arguments())
            .get_matches();

        // Initialize component container.
        let mut container = known_components
            .build_with_arguments(&args)
            .expect("failed to initialize component container");

        contract_client!($signer, $contract, args, container)
    }};
}

#[cfg(feature = "benchmark")]
#[macro_export]
macro_rules! benchmark_app {
    () => {{
        use std::sync::{Arc, Mutex};

        let known_components = $crate::components::create_known_components();
        let args = Arc::new(
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
                .args(&known_components.get_arguments())
                .get_matches(),
        );

        // Initialize component container.
        let container = known_components
            .build_with_arguments(&args)
            .expect("failed to initialize component container");
        let container = Arc::new(Mutex::new(container));

        (args, container)
    }};
}

#[cfg(feature = "benchmark")]
#[macro_export]
macro_rules! benchmark_client {
    ($app:ident, $signer:ident, $contract:ident, $init:expr, $scenario:expr, $finalize:expr) => {{
        let (args, container) = ($app.0.clone(), $app.1.clone());
        let signer = $signer.clone();

        let benchmark = $crate::benchmark::Benchmark::new(
            value_t!(args, "benchmark-runs", usize).unwrap_or_else(|e| e.exit()),
            value_t!(args, "benchmark-threads", usize).unwrap_or_else(|e| e.exit()),
            move || {
                let args = args.clone();
                let shared_container = container.clone();
                let mut container = shared_container.lock().unwrap();
                let signer = signer.clone();

                contract_client!(signer, $contract, args, container)
            },
        );

        let results = benchmark.run($init, $scenario, $finalize);
        println!("------ {} ------", stringify!($scenario));
        results.show();
        println!("");
    }};
}
