//! Prometheus metric server.
use std::{net, sync::Arc};

use hyper::{service::service_fn_ok, Body, Request, Response, Server};
use prometheus::{self, Encoder};

use ekiden_common::{environment::Environment, futures::prelude::*};

/// Prometheus metrics endpoint.
fn metrics_service(_request: Request<Body>) -> Response<Body> {
    let encoder = prometheus::TextEncoder::new();
    let mut buffer = Vec::new();
    encoder.encode(&prometheus::gather(), &mut buffer).unwrap();

    Response::builder()
        .header("Content-Type", encoder.format_type())
        .body(buffer.into())
        .unwrap()
}

/// Start an HTTP server for Prometheus metrics.
pub fn start(environment: Arc<Environment>, address: net::SocketAddr) {
    let server = Server::bind(&address)
        .serve(|| service_fn_ok(metrics_service))
        .map_err(|error| {
            error!("Error while serving Prometheus endpoint: {:?}", error);
        });

    info!("Starting Prometheus metrics endpoint on {}", address);
    environment.spawn(server.into_box());
}
