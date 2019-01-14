//! Scheduler gRPC client.
use std::convert::TryFrom;
use std::error::Error as StdError;
use std::sync::Arc;

use grpcio::{Channel, ChannelBuilder};

use ekiden_common::bytes::B256;
use ekiden_common::environment::Environment;
use ekiden_common::error::Error;
use ekiden_common::futures::prelude::*;
use ekiden_common::identity::NodeIdentity;
use ekiden_common::node::Node;
use ekiden_common::remote_node::RemoteNode;
use ekiden_scheduler_api as api;
use ekiden_scheduler_base::{Committee, Scheduler};

/// Scheduler client implements the Scheduler interface.
pub struct SchedulerClient(api::SchedulerClient);

impl SchedulerClient {
    pub fn new(channel: Channel) -> Self {
        SchedulerClient(api::SchedulerClient::new(channel))
    }

    pub fn from_node(
        node: &Node,
        environment: Arc<Environment>,
        identity: Arc<NodeIdentity>,
    ) -> Self {
        SchedulerClient::new(node.connect(environment, identity))
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

    fn watch_committees(&self) -> BoxStream<Committee> {
        let req = api::WatchRequest::new();
        match self.0.watch_committees(&req) {
            Ok(s) => Box::new(s.then(|result| match result {
                Ok(r) => Ok(Committee::try_from(r.get_committee().to_owned())?),
                Err(e) => Err(Error::new(e.description())),
            })),
            Err(e) => Box::new(stream::once::<Committee, _>(Err(Error::new(
                e.description(),
            )))),
        }
    }
}

// Register for dependency injection.
create_component!(
    remote,
    "scheduler-backend",
    SchedulerClient,
    Scheduler,
    (|container: &mut Container| -> Result<Box<Any>> {
        let environment: Arc<Environment> = container.inject()?;

        // "node-host" and "node-port" arguments.
        let remote_node: Arc<RemoteNode> = container.inject()?;

        let channel = ChannelBuilder::new(environment.grpc()).connect(&format!(
            "{}:{}",
            remote_node.get_node_host(),
            remote_node.get_node_port(),
        ));

        let instance: Arc<Scheduler> = Arc::new(SchedulerClient::new(channel));
        Ok(Box::new(instance))
    }),
    []
);
