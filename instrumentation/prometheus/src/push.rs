//! Prometheus metric push.
use std::sync::Arc;
use std::time::{Duration, Instant};

use prometheus;

use ekiden_common::environment::Environment;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::prelude::*;
use ekiden_common::tokio::timer::Interval;

fn push_metrics(address: &str) -> Result<()> {
    prometheus::push_metrics(
        "ekiden_push", // TODO: Add optional arguemnt for Job name.
        labels!{}, // TODO: Add optional arguments for labels: labels!{"instance".to_owned() => "HAL-9000".to_owned(),},
        address,
        prometheus::gather(),
    ).unwrap();
    Ok(())
}

/// Start an task for pushing Prometheus metrics.
pub fn start(environment: Arc<Environment>, address: String, period: Duration) {
    let push = Box::new(
        Interval::new(Instant::now(), period)
            .map_err(|error| Error::from(error))
            .for_each(move |_| push_metrics(&address))
            .then(|_| future::ok(())),
    );

    info!("Starting Prometheus metrics push!");
    environment.spawn(push);
}
