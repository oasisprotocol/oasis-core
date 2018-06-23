//! Dependency injection support.
use super::{pusher, server, PrometheusMetricCollector};
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
        // Start Prometheus metrics endpoint or pusher when available.
        #[cfg(any(feature = "server", feature = "pusher"))]
        {
            let environment = container.inject()?;
            let args = container.get_arguments().unwrap();
            let mode = value_t!(args, "prometheus-mode", String);
            let address = value_t!(args, "metrics-addr", SocketAddr);
            match (mode, address) {
                (Ok(mode), Ok(address)) => {
                    if mode == PROMETHEUS_MODE_PULL {
                        server::start(environment, address);
                    } else if mode == PROMETHEUS_MODE_PUSH {
                        pusher::start(environment, address);
                    }
                }
                _ => ()
            }
        }
        let metric_collector: Box<MetricCollector> = Box::new(PrometheusMetricCollector::new());
        Ok(Box::new(metric_collector))
    }),
    [
        Arg::with_name("prometheus-mode")
            .long("prometheus-mode")
            .help("Prometheus mode to be used: pull/push")
            .possible_values(&[PROMETHEUS_MODE_PULL, PROMETHEUS_MODE_PUSH])
            .default_value(PROMETHEUS_MODE_PULL)
            .takes_value(true),
        Arg::with_name("metrics-addr")
            .long("metrics-addr")
            .help("A SocketAddr (as a string) from which to serve metrics to Prometheus.")
            .takes_value(true)
    ]
);
