//! Prometheus metric push.
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use prometheus;

use ekiden_common::environment::Environment;

/// Pushes metrics to Prometheus pushgateway.
pub fn push_metrics(address: &str, job_name: &str, instance_name: &str) {
    prometheus::push_metrics(
        job_name,
        labels!{"instance".to_owned() => instance_name.to_owned(),},
        address,
        prometheus::gather(),
    ).or_else::<prometheus::Error, _>(|err| {
        warn!("Cannot push prometheus metrics: {}", err);
        Ok(())
    })
        .unwrap();
}

/// Start a thread for pushing Prometheus metrics.
pub fn start(
    _environment: Arc<Environment>,
    address: String,
    period: Duration,
    job_name: String,
    instance_name: String,
) {
    // We need to spawn a thread instead of a task because the Prometheus push
    // implementation is blocking.
    thread::spawn(move || {
        info!("Starting Prometheus metrics push");

        loop {
            // Sleep for the given period.
            thread::sleep(period.clone());

            // Try to push metrics.
            push_metrics(&address, &job_name, &instance_name);
        }
    });
}
