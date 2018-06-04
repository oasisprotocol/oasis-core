//! Scheduler gRPC client.
use std::convert::TryFrom;
use std::error::Error as StdError;
use std::sync::Arc;

use grpcio::{self, Channel, ChannelBuilder};

use ekiden_common::bytes::B256;
use ekiden_common::environment::Environment;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, stream, BoxFuture, BoxStream, Executor, Future, Stream};
use ekiden_common::node::Node;
use ekiden_scheduler_api as api;
use ekiden_scheduler_base::{Committee, Scheduler};

/// Scheduler client implements the Scheduler interface.
pub struct SchedulerClient(api::SchedulerClient);

impl SchedulerClient {
    pub fn new(channel: Channel) -> Self {
        SchedulerClient(api::SchedulerClient::new(channel))
    }

    pub fn from_node(node: Node, env: Arc<grpcio::Environment>) -> Self {
        SchedulerClient::new(node.connect(env))
    }
}

impl Scheduler for SchedulerClient {
    fn start(&self, _executor: &mut Executor) {
        // TODO: refactor / remove
    }

    fn get_committees(&self, contract_id: B256) -> BoxFuture<Vec<Committee>> {
        let mut req = api::CommitteeRequest::new();
        req.set_contract_id(contract_id.to_vec());
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

        let args = container.get_arguments().unwrap();
        let channel = ChannelBuilder::new(environment.grpc()).connect(&format!(
            "{}:{}",
            args.value_of("scheduler-client-host").unwrap(),
            args.value_of("scheduler-client-port").unwrap(),
        ));

        let instance: Arc<Scheduler> = Arc::new(SchedulerClient::new(channel));
        Ok(Box::new(instance))
    }),
    [
        Arg::with_name("scheduler-client-host")
            .long("scheduler-client-host")
            .help("(remote scheduler backend) Host that the scheduler client should connect to")
            .takes_value(true)
            .default_value("127.0.0.1"),
        Arg::with_name("scheduler-client-port")
            .long("scheduler-client-port")
            .help("(remote scheduler backend) Port that the scheduler client should connect to")
            .takes_value(true)
            .default_value("42261")
    ]
);
