//! Convenience macros.

/// Generic instrumentation macro.
#[macro_export]
macro_rules! measure {
    ($name:expr, $value:expr) => {
        $crate::metric_collector().collect(&$crate::Metric::builder()
            .name($name)
            .value(Some($value))
            .module_path(Some(module_path!()))
            .file(Some(file!()))
            .line(Some(line!()))
            .build());
    };
}

/// Create a new metric with the given configuration.
///
/// # Examples
///
/// To configure buckets for a histogram:
/// ```
/// measure_configure!(
///     "my_histogram",
///     "This is my lovely histogram.",
///     MetricConfig::Histogram {
///         buckets: [0.0, 1.0, 2.0].to_vec()
///     }
/// );
/// ```
#[macro_export]
macro_rules! measure_configure {
    ($name:expr, $description:expr, $config:expr) => {{
        use $crate::MetricConfig;

        $crate::metric_collector().collect(&$crate::Metric::builder()
            .name($name)
            .description(Some($description))
            .config(Some($config))
            .module_path(Some(module_path!()))
            .file(Some(file!()))
            .line(Some(line!()))
            .build());
    }};
}

/// Increment an instrumentation counter.
///
/// If no value is specified it increments the counter by one.
///
/// # Examples
///
/// ```
/// measure_counter_inc!("my_counter");
/// measure_counter_inc!("my_counter", 10);
/// ```
#[macro_export]
macro_rules! measure_counter_inc {
    ($name:expr, $value:expr) => {
        measure!($name, $crate::MetricValue::Counter($value as f64));
    };

    ($name:expr) => {
        measure_counter_inc!($name, 1);
    };
}

/// Set an instrumentation gauge.
///
/// # Examples
///
/// ```
/// measure_gauge!("my_gauge", 10);
/// ```
#[macro_export]
macro_rules! measure_gauge {
    ($name:expr, $value:expr) => {
        measure!($name, $crate::MetricValue::Gauge($value as f64));
    };
}

/// Observes a value and stores it into an instrumentation histogram.
///
/// # Examples
///
/// ```
/// measure_histogram!("my_histogram", 1.3);
/// ```
#[macro_export]
macro_rules! measure_histogram {
    ($name:expr, $value:expr) => {
        measure!($name, $crate::MetricValue::Histogram($value as f64));
    };
}

/// Times a block of code and stores the elapsed time (in seconds) into an
/// instrumentation histogram.
///
/// # Examples
///
/// ```
/// {
///     measure_histogram_timer!("my_timer");
///     // ...
///     // ...
/// } // <- elapsed time recorded here
/// ```
#[macro_export]
macro_rules! measure_histogram_timer {
    ($name:expr) => {
        let _timer = $crate::timer::Timer::new(|elapsed| {
            measure_histogram!($name, elapsed);
        });
    };
}
