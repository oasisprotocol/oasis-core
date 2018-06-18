//! Dependency injection support.
use std::net::SocketAddr;

use ekiden_instrumentation::MetricCollector;

use super::{server, PrometheusMetricCollector};

// Make Prometheus service injectable.
create_component!(
    prometheus,
    "metric-collector",
    PrometheusMetricCollector,
    MetricCollector,
    (|container: &mut Container| -> Result<Box<Any>> {
        // Start Prometheus metrics endpoint when available.
        #[cfg(feature = "server")]
        {
            let environment = container.inject()?;
            let args = container.get_arguments().unwrap();
            if let Ok(address) = value_t!(args, "metrics-addr", SocketAddr) {
                server::start(environment, address);
            }
        }

        let metric_collector: Box<MetricCollector> = Box::new(PrometheusMetricCollector::new());
        Ok(Box::new(metric_collector))
    }),
    [Arg::with_name("metrics-addr")
        .long("metrics-addr")
        .help("A SocketAddr (as a string) from which to serve metrics to Prometheus.")
        .takes_value(true)]
);
