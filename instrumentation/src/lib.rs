//! Instrumentation.
#[macro_use]
extern crate failure;

use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

#[macro_use]
pub mod macros;
pub mod timer;

// The METRIC_COLLECTOR static holds a pointer to the global metric collector. It is
// protected by the STATE static which determines whether METRIC_COLLECTOR has been
// initialized yet.
static mut METRIC_COLLECTOR: &'static MetricCollector = &NopMetricCollector;
static STATE: AtomicUsize = ATOMIC_USIZE_INIT;

// There are three different states that we care about: the metric collector's
// uninitialized, the metric collector's initializing (set_metric_collector's been
// called but METRIC_COLLECTOR hasn't actually been set yet), or the metric
// collector's active.
const UNINITIALIZED: usize = 0;
const INITIALIZING: usize = 1;
const INITIALIZED: usize = 2;

/// Value of a metric.
#[derive(Clone, Copy, Debug)]
pub enum MetricValue {
    /// Counter-type metric with a given value increment.
    Counter(f64),
    /// Gauge-type metric with a given observation.
    Gauge(f64),
    /// Histogram-type metric with a given observation.
    Histogram(f64),
}

/// Metric configuration.
#[derive(Clone, Debug)]
pub enum MetricConfig {
    /// Counter.
    Counter,
    /// Gauge.
    Gauge,
    /// Histogram.
    Histogram { buckets: Vec<f64> },
}

/// Default histogram buckets.
pub const HISTOGRAM_DEFAULT_BUCKETS: &[f64; 11] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// A metric.
#[derive(Clone, Debug)]
pub struct Metric<'a> {
    name: &'a str,
    description: Option<&'a str>,
    module_path: Option<&'a str>,
    file: Option<&'a str>,
    line: Option<u32>,
    value: Option<MetricValue>,
    config: Option<MetricConfig>,
}

impl<'a> Metric<'a> {
    /// Start building a new metric.
    #[inline]
    pub fn builder() -> MetricBuilder<'a> {
        MetricBuilder::new()
    }

    /// Get name.
    #[inline]
    pub fn name(&self) -> &'a str {
        &self.name
    }

    /// Get description.
    #[inline]
    pub fn description(&self) -> Option<&'a str> {
        self.description
    }

    /// Get module path.
    #[inline]
    pub fn module_path(&self) -> Option<&'a str> {
        self.module_path
    }

    /// Get file.
    #[inline]
    pub fn file(&self) -> Option<&'a str> {
        self.file
    }

    /// Get line.
    #[inline]
    pub fn line(&self) -> Option<u32> {
        self.line
    }

    /// Get value.
    #[inline]
    pub fn value(&self) -> Option<MetricValue> {
        self.value
    }

    /// Get configuration.
    #[inline]
    pub fn config(&self) -> Option<MetricConfig> {
        if self.config.is_none() {
            match self.value {
                Some(MetricValue::Counter(_)) => return Some(MetricConfig::Counter),
                Some(MetricValue::Gauge(_)) => return Some(MetricConfig::Gauge),
                Some(MetricValue::Histogram(_)) => {
                    return Some(MetricConfig::Histogram {
                        buckets: HISTOGRAM_DEFAULT_BUCKETS.to_vec(),
                    });
                }
                None => {}
            }
        }

        self.config.as_ref().cloned()
    }
}

/// Metric builder.
pub struct MetricBuilder<'a> {
    metric: Metric<'a>,
}

impl<'a> MetricBuilder<'a> {
    /// Create a new metric builder.
    #[inline]
    pub fn new() -> Self {
        Self {
            metric: Metric {
                name: "",
                description: None,
                module_path: None,
                file: None,
                line: None,
                value: None,
                config: None,
            },
        }
    }

    /// Set [`name`].
    #[inline]
    pub fn name(&mut self, name: &'a str) -> &mut Self {
        self.metric.name = name;
        self
    }

    /// Set [`description`].
    #[inline]
    pub fn description(&mut self, description: Option<&'a str>) -> &mut Self {
        self.metric.description = description;
        self
    }

    /// Set [`module_path`].
    #[inline]
    pub fn module_path(&mut self, module_path: Option<&'a str>) -> &mut Self {
        self.metric.module_path = module_path;
        self
    }

    /// Set [`file`].
    #[inline]
    pub fn file(&mut self, file: Option<&'a str>) -> &mut Self {
        self.metric.file = file;
        self
    }

    /// Set [`line`].
    #[inline]
    pub fn line(&mut self, line: Option<u32>) -> &mut Self {
        self.metric.line = line;
        self
    }

    /// Set [`value`].
    #[inline]
    pub fn value(&mut self, value: Option<MetricValue>) -> &mut Self {
        self.metric.value = value;
        self
    }

    /// Set [`config`].
    #[inline]
    pub fn config(&mut self, config: Option<MetricConfig>) -> &mut Self {
        self.metric.config = config;
        self
    }

    /// Finish building a metric.
    #[inline]
    pub fn build(&self) -> Metric {
        self.metric.clone()
    }
}

/// Trait defining the operations of a metric collector.
pub trait MetricCollector: Sync + Send {
    /// Collects a metric.
    fn collect(&self, metric: &Metric);
}

/// A no-op metric collector which discards all metrics.
struct NopMetricCollector;

impl MetricCollector for NopMetricCollector {
    fn collect(&self, _metric: &Metric) {}
}

#[derive(Debug, Fail)]
pub enum MetricCollectorError {
    #[fail(display = "metric collector already initialized")]
    AlreadyInitialized,
}

/// Set the global metric collector to `metric_collector`.
///
/// This is a convenience function over `set_metric_collector` which allows one
/// to pass a `Box<MetricCollector>` instead of a `&'static MetricCollector`.
pub fn set_boxed_metric_collector(
    metric_collector: Box<MetricCollector>,
) -> Result<(), MetricCollectorError> {
    set_metric_collector_inner(|| Box::leak(metric_collector))
}

/// Set the global metric collector to `metric_collector`.
///
/// This function may only be called once in the lifetime of a program. Any metric
/// emits that occur before the call to `set_metric_collector` completes will be
/// ignored.
///
/// This function does not typically need to be called manually. Metric collector
/// implementations should provide an initialization method that installs the
/// metric collector internally.
pub fn set_metric_collector(
    metric_collector: &'static MetricCollector,
) -> Result<(), MetricCollectorError> {
    set_metric_collector_inner(|| metric_collector)
}

fn set_metric_collector_inner<F>(make_metric_collector: F) -> Result<(), MetricCollectorError>
where
    F: FnOnce() -> &'static MetricCollector,
{
    unsafe {
        if STATE.compare_and_swap(UNINITIALIZED, INITIALIZING, Ordering::SeqCst) != UNINITIALIZED {
            return Err(MetricCollectorError::AlreadyInitialized);
        }

        METRIC_COLLECTOR = make_metric_collector();
        STATE.store(INITIALIZED, Ordering::SeqCst);
        Ok(())
    }
}

/// Returns a reference to the metric collector.
///
/// If a metric collector has not been set, a no-op implementation is returned.
pub fn metric_collector() -> &'static MetricCollector {
    unsafe {
        if STATE.load(Ordering::SeqCst) != INITIALIZED {
            static NOP: NopMetricCollector = NopMetricCollector;
            &NOP
        } else {
            METRIC_COLLECTOR
        }
    }
}
