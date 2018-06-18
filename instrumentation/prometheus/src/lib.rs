//! Prometheus frontend for Ekiden instrumentation.
//!
//! All metrics will be registered into the default Prometheus registry so
//! metrics can be gatherd by using `prometheus::gather` as usual.
#[cfg_attr(test, macro_use)]
extern crate ekiden_instrumentation;

#[cfg(feature = "server")]
extern crate ekiden_common;
#[cfg(feature = "server")]
extern crate futures;
#[cfg(feature = "server")]
extern crate http;
#[cfg(feature = "server")]
extern crate hyper;
extern crate prometheus;
#[cfg(feature = "server")]
#[macro_use]
extern crate ekiden_di;
#[macro_use]
extern crate log;
#[cfg(feature = "di")]
#[macro_use]
extern crate clap;

#[cfg(feature = "di")]
pub mod di;
#[cfg(feature = "server")]
pub mod server;

use std::collections::HashMap;
use std::sync::RwLock;

use ekiden_instrumentation::{set_boxed_metric_collector, Metric, MetricCollector,
                             MetricCollectorError, MetricConfig, MetricValue};

enum PrometheusMetric {
    Counter(prometheus::Counter),
    Gauge(prometheus::Gauge),
    Histogram(prometheus::Histogram),
}

impl PrometheusMetric {
    pub fn get_collector(&self) -> Box<prometheus::core::Collector> {
        match *self {
            PrometheusMetric::Counter(ref counter) => Box::new(counter.clone()),
            PrometheusMetric::Gauge(ref gauge) => Box::new(gauge.clone()),
            PrometheusMetric::Histogram(ref histogram) => Box::new(histogram.clone()),
        }
    }
}

/// Prometheus metric collector.
pub struct PrometheusMetricCollector {
    metrics: RwLock<HashMap<String, PrometheusMetric>>,
}

impl PrometheusMetricCollector {
    pub fn new() -> Self {
        Self {
            metrics: RwLock::new(HashMap::new()),
        }
    }
}

impl MetricCollector for PrometheusMetricCollector {
    fn collect(&self, metric: &Metric) {
        // Optimistically check if a metric is already registered.
        {
            let metrics = self.metrics.read().unwrap();
            match metrics.get(metric.name()) {
                Some(prometheus_metric) => {
                    process_metric(metric, prometheus_metric);
                    return;
                }
                None => {}
            }
        }

        // Metric may not yet exist.
        {
            let mut metrics = self.metrics.write().unwrap();

            // Check again if it exists as it may have been added.
            match metrics.get(metric.name()) {
                Some(prometheus_metric) => {
                    process_metric(metric, prometheus_metric);
                    return;
                }
                None => {}
            }

            // Metric does not yet exist, create it and then process.
            let prometheus_metric = create_metric(metric);
            process_metric(metric, &prometheus_metric);
            prometheus::register(prometheus_metric.get_collector()).unwrap();
            metrics.insert(metric.name().to_owned(), prometheus_metric);
        }
    }
}

/// Create a Prometheus metric from a `Metric`.
///
/// # Panics
///
/// This function will panic if the metric does not have any config or if the
/// Prometheus metric cannot be created for any reason.
fn create_metric(metric: &Metric) -> PrometheusMetric {
    let name;
    if let Some(module_path) = metric.module_path() {
        name = format!(
            "{}_{}",
            module_path.to_lowercase().replace("::", "_"),
            metric.name()
        );
    } else {
        name = metric.name().to_owned();
    }

    let help;
    if let Some(description) = metric.description() {
        help = description.to_owned();
    } else {
        help = name.clone();
    }

    match metric.config().unwrap() {
        MetricConfig::Counter => {
            PrometheusMetric::Counter(prometheus::Counter::new(name, help).unwrap())
        }
        MetricConfig::Gauge => PrometheusMetric::Gauge(prometheus::Gauge::new(name, help).unwrap()),
        MetricConfig::Histogram { buckets } => PrometheusMetric::Histogram(
            prometheus::Histogram::with_opts(
                prometheus::HistogramOpts::new(name, help).buckets(buckets),
            ).unwrap(),
        ),
    }
}

/// Process a `Metric` for a given `PrometheusMetric`.
fn process_metric(metric: &Metric, prometheus_metric: &PrometheusMetric) {
    let value = if let Some(value) = metric.value() {
        value
    } else {
        return;
    };

    match (value, prometheus_metric) {
        (MetricValue::Counter(value), &PrometheusMetric::Counter(ref counter)) => {
            counter.inc_by(value);
        }
        (MetricValue::Gauge(value), &PrometheusMetric::Gauge(ref gauge)) => {
            gauge.set(value);
        }
        (MetricValue::Histogram(value), &PrometheusMetric::Histogram(ref histogram)) => {
            histogram.observe(value);
        }
        _ => panic!("incorrect value {:?} for metric {}", value, metric.name()),
    }
}

/// Initialize the Prometheus metric collector.
///
/// This function may only be called once in the lifetime of a program. Any metric
/// emits that occur before the call to `set_metric_collector` completes will be
/// ignored.
pub fn init() -> Result<(), MetricCollectorError> {
    set_boxed_metric_collector(Box::new(PrometheusMetricCollector::new()))
}

#[cfg(feature = "di")]
#[doc(hidden)]
pub use self::di::*;

#[cfg(test)]
mod tests {
    use std::{thread, time};

    use super::*;

    #[test]
    fn test_prometheus() {
        const THREADS: u64 = 10;

        init().unwrap();

        // Test some counters and histograms.
        measure_configure!(
            "my_histogram",
            "This is my lovely histogram.",
            MetricConfig::Histogram {
                buckets: vec![0.0, 1.0, 2.0],
            }
        );

        (0..THREADS)
            .map(|_| {
                thread::spawn(|| {
                    measure_counter_inc!("my_counter", 10);
                    measure_counter_inc!("my_counter");
                    measure_gauge!("my_gauge", 42);
                    measure_histogram!("my_histogram", 1.3);
                })
            })
            .for_each(|thread| thread.join().unwrap());

        // Test timer.
        {
            measure_histogram_timer!("my_timer");
            thread::sleep(time::Duration::from_secs(1));
        }

        // Gather collected values.
        let metrics = prometheus::gather();
        assert_eq!(metrics.len(), 4);

        for family in metrics {
            match family.get_name() {
                "ekiden_instrumentation_prometheus_tests_my_counter" => {
                    assert_eq!(
                        family.get_field_type(),
                        prometheus::proto::MetricType::COUNTER
                    );
                    assert_eq!(
                        family.get_metric()[0].get_counter().get_value(),
                        (11 * THREADS) as f64
                    );
                }
                "ekiden_instrumentation_prometheus_tests_my_gauge" => {
                    assert_eq!(
                        family.get_field_type(),
                        prometheus::proto::MetricType::GAUGE
                    );
                    assert_eq!(family.get_metric()[0].get_gauge().get_value(), 42f64);
                }
                "ekiden_instrumentation_prometheus_tests_my_histogram" => {
                    assert_eq!(
                        family.get_field_type(),
                        prometheus::proto::MetricType::HISTOGRAM
                    );
                    assert_eq!(family.get_help(), "This is my lovely histogram.");
                    assert_eq!(family.get_metric()[0].get_histogram().get_bucket().len(), 3);
                    assert_eq!(
                        family.get_metric()[0].get_histogram().get_bucket()[0]
                            .get_cumulative_count(),
                        0
                    );
                    assert_eq!(
                        family.get_metric()[0].get_histogram().get_bucket()[1]
                            .get_cumulative_count(),
                        0
                    );
                    assert_eq!(
                        family.get_metric()[0].get_histogram().get_bucket()[2]
                            .get_cumulative_count(),
                        THREADS
                    );
                    assert_eq!(
                        family.get_metric()[0].get_histogram().get_sample_count(),
                        THREADS
                    );
                }
                "ekiden_instrumentation_prometheus_tests_my_timer" => {
                    assert_eq!(
                        family.get_field_type(),
                        prometheus::proto::MetricType::HISTOGRAM
                    );
                    assert_eq!(
                        family.get_metric()[0].get_histogram().get_bucket().len(),
                        11
                    );
                    assert_eq!(family.get_metric()[0].get_histogram().get_sample_count(), 1);
                }
                name => panic!("unexpected metric: {}", name),
            }
        }
    }
}
