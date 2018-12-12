extern crate protobuf;

extern crate ekiden_core;
extern crate ekiden_trusted;

#[macro_use]
extern crate ekiden_enclave_logger;

extern crate test_logger_api;

use std::str::FromStr;

use test_logger_api::{with_api, LoggerInitResponse};

use ekiden_core::error::Result;
use ekiden_trusted::db::{DBKeyManagerConfig, Database, DatabaseHandle};
use ekiden_trusted::enclave::enclave_init;
use ekiden_trusted::runtime::create_runtime;
use ekiden_trusted::runtime::dispatcher::RuntimeCallContext;

enclave_init!();

// Create enclave contract interface.
with_api! {
    create_runtime!(api);
}

pub fn init(_ctx: &RuntimeCallContext) -> Result<LoggerInitResponse> {
    let mut r: LoggerInitResponse = LoggerInitResponse::new();

    match ekiden_enclave_logger::init() {
        Ok(_) => { r.set_ok(true); },
        Err(e) => { r.set_ok(false); r.set_value(String::from(e)); },
    }

    Ok(r);
}

pub fn write_error(message: &str, _ctx: &RuntimeCallContext) -> Result<()> {
    ekiden_enclave_logger::error!("[test test-logger enclave] Received error message: {}", message);
    Ok(())
}

pub fn write_warn(message: &str, _ctx: &RuntimeCallContext) -> Result<()> {
    ekiden_enclave_logger::warn!("[test test-logger enclave] Received warn message: {}", message);
    Ok(())
}

pub fn write_info(message: &str, _ctx: &RuntimeCallContext) -> Result<()> {
    ekiden_enclave_logger::info!("[test test-logger enclave] Received info message: {}", message);
    Ok(())
}

pub fn write_debug(message: &str, _ctx: &RuntimeCallContext) -> Result<()> {
    ekiden_enclave_logger::debug!("[test test-logger enclave] Received debug message: {}", message);
    Ok(())
}

pub fn write_trace(message: &str, _ctx: &RuntimeCallContext) -> Result<()> {
    ekiden_enclave_logger::trace!("[test test-logger enclave] Received trace message: {}", message);
    Ok(())
}
