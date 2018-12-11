// Re-exports needed in exported macros.
pub use log::LevelFilter;
pub use pretty_env_logger::formatted_builder;

pub use ekiden_core::bytes::B256;
pub use ekiden_core::enclave::quote::MrEnclave;
pub use ekiden_instrumentation::set_boxed_metric_collector;
pub use ekiden_instrumentation::MetricCollector;
pub use ekiden_tracing::get_arguments as get_tracing_arguments;
pub use ekiden_tracing::report_forever;

#[macro_export]
macro_rules! default_app {
    () => {{
        use $crate::macros::LevelFilter;

        // Initialize logger. If another logger is already initialized, move on.
        drop(
            $crate::macros::formatted_builder()
                .unwrap()
                .filter(None, LevelFilter::Trace)
                .filter(Some("mio"), LevelFilter::Warn)
                .filter(Some("tokio_threadpool"), LevelFilter::Warn)
                .filter(Some("tokio_reactor"), LevelFilter::Warn)
                .try_init(),
        );

        App::new(concat!(crate_name!(), " client"))
            .about(crate_description!())
            .author(crate_authors!())
            .version(crate_version!())
            .arg(
                Arg::with_name("test-runtime-id")
                    .long("test-runtime-id")
                    .help("TEST ONLY OPTION: override runtime identifier")
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
            .args(&$crate::macros::get_tracing_arguments())
    }};
}

#[macro_export]
macro_rules! runtime_client {
    ($runtime:ident, $args:ident, $container:ident) => {{
        use $crate::macros::*;

        // Initialize metric collector (if not already initialized).
        if let Ok(metrics) = $container.inject_owned::<$crate::macros::MetricCollector>() {
            $crate::macros::set_boxed_metric_collector(metrics).unwrap();
        }

        $runtime::Client::new(
            $crate::args::get_runtime_id(&$args),
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
            $container.inject().unwrap(),
            $container.inject().unwrap(),
        )
    }};
    ($runtime:ident) => {{
        let known_components = $crate::components::create_known_components();
        let args = default_app!()
            .args(&known_components.get_arguments())
            .get_matches();

        // Initialize component container.
        let mut container = known_components
            .build_with_arguments(&args)
            .expect("failed to initialize component container");

        // Initialize tracing.
        $crate::macros::report_forever("runtime-client", &args);

        runtime_client!($runtime, args, container)
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
                .arg(
                    Arg::with_name("output-format")
                        .long("output-format")
                        .help("Output format")
                        .possible_values(&["text", "json"])
                        .takes_value(true)
                        .default_value("text"),
                )
                .arg(
                    Arg::with_name("output-title-prefix")
                        .long("output-title-prefix")
                        .help("Output title prefix")
                        .takes_value(true)
                        .default_value(""),
                )
                .args(&known_components.get_arguments())
                .get_matches(),
        );

        // Initialize component container.
        let mut container = known_components
            .build_with_arguments(&args)
            .expect("failed to initialize component container");

        // Initialize metric collector.
        let metrics = container
            .inject_owned::<$crate::macros::MetricCollector>()
            .expect("failed to inject MetricCollector");
        $crate::macros::set_boxed_metric_collector(metrics).unwrap();

        let container = Arc::new(Mutex::new(container));

        // Initialize tracing.
        $crate::macros::report_forever("runtime-client", &args);

        (args, container)
    }};
}

#[cfg(feature = "benchmark")]
#[macro_export]
macro_rules! benchmark_client {
    ($app:ident, $runtime:ident, $init:expr, $scenario:expr, $finalize:expr) => {{
        use $crate::benchmark::OutputFormat;

        let (args, container) = ($app.0.clone(), $app.1.clone());

        let output_format = match args.value_of("output-format").unwrap() {
            "text" => OutputFormat::Text,
            "json" => OutputFormat::Json,
            _ => unreachable!(),
        };

        let title = if let Some(title_prefix) = args.value_of("output-title-prefix") {
            format!("{} - {}", title_prefix, stringify!($scenario))
        } else {
            format!("{}", stringify!($scenario))
        };

        let benchmark = $crate::benchmark::Benchmark::new(
            value_t!(args, "benchmark-runs", usize).unwrap_or_else(|e| e.exit()),
            value_t!(args, "benchmark-threads", usize).unwrap_or_else(|e| e.exit()),
            move || {
                let args = args.clone();
                let shared_container = container.clone();
                let mut container = shared_container.lock().unwrap();

                runtime_client!($runtime, args, container)
            },
        );

        let results = benchmark.run(
            $init,
            $scenario,
            $finalize,
            output_format == OutputFormat::Text,
        );

        results.show(&title, output_format);
    }};
}

#[cfg(feature = "benchmark")]
#[macro_export]
macro_rules! benchmark_multiple {
    ($app:ident, $runtime:ident, [$($scenario:expr),*]) => {
        $(
            benchmark_client!($app, $runtime, None, $scenario, None);
        )*
    }
}
