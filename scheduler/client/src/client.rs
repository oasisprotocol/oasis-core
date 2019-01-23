//! Scheduler gRPC client.
use std::convert::TryFrom;
use std::error::Error as StdError;

use grpcio::Channel;

use ekiden_common::bytes::B256;
use ekiden_common::error::Error;
use ekiden_common::futures::prelude::*;
use ekiden_scheduler_api as api;
use ekiden_scheduler_base::{Committee, Scheduler};

/// Scheduler client implements the Scheduler interface.
pub struct SchedulerClient(api::SchedulerClient);

impl SchedulerClient {
    pub fn new(channel: Channel) -> Self {
        SchedulerClient(api::SchedulerClient::new(channel))
    }
}

impl Scheduler for SchedulerClient {
    fn get_committees(&self, runtime_id: B256) -> BoxFuture<Vec<Committee>> {
        let mut req = api::CommitteeRequest::new();
        req.set_runtime_id(runtime_id.to_vec());
        match self.0.get_committees_async(&req) {
            Ok(f) => Box::new(f.map(|r| {
                let mut committees = Vec::new();
                for member in r.get_committee() {
                    committees.push(Committee::try_from(member.to_owned()).unwrap());
                }
                committees
            }).map_err(|e| Error::new(e.description()))),
            Err(e) => Box::new(future::err(Error::new(e.description()))),
        }
    }
}
