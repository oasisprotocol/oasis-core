extern crate ekiden_core;
extern crate ekiden_trusted;

extern crate log;
use log::{debug, error, info, trace, warn};
use std::str::FromStr;

extern crate serde_json;
extern crate test_logger_api;

use ekiden_core::error::Result;
use ekiden_trusted::enclave::enclave_init;
use ekiden_trusted::runtime::create_runtime;
use ekiden_trusted::runtime::dispatcher::RuntimeCallContext;
use test_logger_api::with_api;

enclave_init!();

// Create enclave contract interface.
with_api! {
    create_runtime!(api);
}

pub fn set_max_level(level_filter: &String, _ctx: &RuntimeCallContext) -> Result<()> {
    info!("Setting max level filter: \"{}\".", level_filter);
    log::set_max_level(log::LevelFilter::from_str(level_filter).unwrap());
    Ok(())
}

pub fn write_error(message: &String, _ctx: &RuntimeCallContext) -> Result<()> {
    error!("Received error message: \"{}\". If this appeared in the worker's log, then logging OCALLs work ;)", message);
    Ok(())
}

pub fn write_warn(message: &String, _ctx: &RuntimeCallContext) -> Result<()> {
    warn!("Received warn message: \"{}\". If this appeared in the worker's log, then logging OCALLs work ;)", message);
    Ok(())
}

pub fn write_info(message: &String, _ctx: &RuntimeCallContext) -> Result<()> {
    info!("Received info message: \"{}\". If this appeared in the worker's log, then logging OCALLs work ;)", message);
    Ok(())
}

pub fn write_debug(message: &String, _ctx: &RuntimeCallContext) -> Result<()> {
    debug!("Received debug message: \"{}\". If this appeared in the worker's log, then logging OCALLs work ;)", message);
    Ok(())
}

pub fn write_trace(message: &String, _ctx: &RuntimeCallContext) -> Result<()> {
    trace!("Received trace message: \"{}\". If this appeared in the worker's log, then logging OCALLs work ;)", message);
    Ok(())
}
