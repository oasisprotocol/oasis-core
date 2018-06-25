//! Dependency injection support.
use std::net::SocketAddr;
use std::time::Duration;

use ekiden_instrumentation::MetricCollector;

use super::{push, server, PrometheusMetricCollector};

const PROMETHEUS_MODE_PULL: &'static str = "pull";
const PROMETHEUS_MODE_PUSH: &'static str = "push";

// Make Prometheus service injectable.
create_component!(
    prometheus,
    "metric-collector",
    PrometheusMetricCollector,
    MetricCollector,
    (|container: &mut Container| -> Result<Box<Any>> {
        // Start Prometheus metrics endpoint or push task when available.
        #[cfg(any(feature = "server", feature = "push"))]
        {
            let environment = container.inject()?;
            let args = container.get_arguments().unwrap();
            let mode = value_t!(args, "prometheus-mode", String);
            match mode.as_ref().map(|x| x.as_ref()) {
                Ok(PROMETHEUS_MODE_PULL) => {
                    if let Ok(address) = value_t!(args, "prometheus-metrics-addr", SocketAddr) {
                        server::start(environment, address);
                    }
                }
                Ok(PROMETHEUS_MODE_PUSH) => {
                    if let Ok(address) = value_t!(args, "prometheus-metrics-addr", String) {
                        let interval = value_t!(args, "prometheus-push-interval", u64).unwrap_or(5);
                        let job = value_t!(args, "prometheus-push-job-name", String).unwrap();
                        let instance = value_t!(args, "prometheus-push-instance-label", String).unwrap();
                        push::start(environment, address, Duration::from_secs(interval), job, instance);
                    }
                }
                _ => (),
            }
        }
        let metric_collector: Box<MetricCollector> = Box::new(PrometheusMetricCollector::new());
        Ok(Box::new(metric_collector))
    }),
    [
        Arg::with_name("prometheus-mode")
            .long("prometheus-mode")
            .possible_values(&[PROMETHEUS_MODE_PULL, PROMETHEUS_MODE_PUSH])
            .takes_value(true),
        Arg::with_name("prometheus-push-interval")
            .long("prometheus-push-interval")
            .help("Push interval in seconds (only used if using push mode).")
            .takes_value(true),
        Arg::with_name("prometheus-push-job-name")
            .long("prometheus-push-job-name")
            .help("Prometheus `job` name used if using push mode.")
            .required_if("prometheus-mode", PROMETHEUS_MODE_PUSH)
            .takes_value(true),
        Arg::with_name("prometheus-push-instance-label")
            .long("prometheus-push-instance-label")
            .help("Prometheus `instance` label used if using push mode.")
            .required_if("prometheus-mode", PROMETHEUS_MODE_PUSH)
            .takes_value(true),
        Arg::with_name("prometheus-metrics-addr")
            .long("prometheus-metrics-addr")
            .help("If pull mode: A SocketAddr (as a string) from which to serve metrics to Prometheus. If push mode: prometheus 'pushgateway' address.")
            .takes_value(true)
    ]
);
