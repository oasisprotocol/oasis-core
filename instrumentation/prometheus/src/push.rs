//! Prometheus metric push.
use std::sync::Arc;
use std::time::{Duration, Instant};

use prometheus;

use ekiden_common::environment::Environment;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::prelude::*;
use ekiden_common::tokio::timer::Interval;

/// Pushes metrics to Prometheus pushgateway.
pub fn push_metrics(address: &str, job_name: &str, instance_name: &str) -> Result<()> {
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
    Ok(())
}

/// Start a task for pushing Prometheus metrics.
pub fn start(
    environment: Arc<Environment>,
    address: String,
    period: Duration,
    job_name: String,
    instance_name: String,
) {
    let push = Box::new(
        Interval::new(Instant::now(), period)
            .map_err(|error| Error::from(error))
            .for_each(move |_| push_metrics(&address, &job_name, &instance_name))
            .then(|_| future::ok(())),
    );

    info!("Starting Prometheus metrics push!");
    environment.spawn(push);
}
