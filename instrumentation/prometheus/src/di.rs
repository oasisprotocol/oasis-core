//! Dependency injection support.
use super::{server, PrometheusMetricCollector};
use ekiden_instrumentation::MetricCollector;
use std::net::SocketAddr;

const PROMETHEUS_MODE_PULL: &'static str = "pull";
const PROMETHEUS_MODE_PUSH: &'static str = "push";

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
    [
        Arg::with_name("prometheus-mode")
            .long("prometheus-mode")
            // TODO continue...
        Arg::with_name("metrics-addr")
            .long("metrics-addr")
            .help("A SocketAddr (as a string) from which to serve metrics to Prometheus.")
            .takes_value(true)
    ]
);
