#![feature(use_extern_macros)]

use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::Mutex;

extern crate clap;
use clap::value_t_or_exit;
extern crate futures;
use futures::future::Executor;
use futures::future::Future;
use futures::future::Shared;
extern crate log;
use log::log;
use log::trace;
use log::warn;
extern crate rusoto_core;
extern crate tokio_core;

extern crate ekiden_common;
use ekiden_common::bytes::H256;
use ekiden_common::error::Error;
use ekiden_common::futures::BoxFuture;
use ekiden_common::futures::FutureExt;
extern crate ekiden_di;
use ekiden_di::create_component;
extern crate ekiden_epochtime;
extern crate ekiden_storage_base;
use ekiden_storage_base::StorageBackend;
extern crate ekiden_storage_dynamodb;
use ekiden_storage_dynamodb::DynamoDbBackend;
extern crate ekiden_storage_persistent;
use ekiden_storage_persistent::PersistentStorageBackend;

type IncomingFuture = BoxFuture<Vec<u8>>;

fn clone_shared<I, E>(
    r: Result<futures::future::SharedItem<I>, futures::future::SharedError<E>>,
) -> Result<I, E>
where
    I: Clone,
    E: Clone,
{
    match r {
        Ok(i) => Ok(i.deref().clone()),
        Err(e) => Err(e.deref().clone()),
    }
}

/// Special instructions to override lookup from the sled layer.
enum AccessedItem {
    /// We're already trying to access this item. Provides a shared future that you can use to wait
    /// on that.
    Incoming(Shared<IncomingFuture>),
    /// We recently added the item, and we're working on writing it.
    Writeback(Vec<u8>),
}

pub struct Rfc0004UBackend {
    /// We do some writeback operations on this separate executor.
    remote: tokio_core::reactor::Remote,
    /// This map lets us look up whether we're already accessing an item.
    accessed: Arc<Mutex<BTreeMap<H256, AccessedItem>>>,

    // Backing layers, as specified in RFC 0004.
    sled: Arc<PersistentStorageBackend>,
    // TODO: remote_sled: Arc<...>,
    aws: Arc<DynamoDbBackend>,
}

impl Rfc0004UBackend {
    pub fn new(
        remote: tokio_core::reactor::Remote,
        sled: Arc<PersistentStorageBackend>,
        // TODO: remote_sled: Arc<...>,
        aws: Arc<DynamoDbBackend>,
    ) -> Self {
        Self {
            remote,
            accessed: Arc::new(Mutex::new(BTreeMap::new())),
            sled,
            // remote_sled,
            aws,
        }
    }
}

impl StorageBackend for Rfc0004UBackend {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let mut accessed_guard = self.accessed.lock().unwrap();
        match accessed_guard.get(&key) {
            Some(&AccessedItem::Incoming(ref f)) => {
                return Box::new(f.clone().then(clone_shared));
            }
            Some(&AccessedItem::Writeback(ref v)) => {
                return Box::new(futures::future::ok(v.clone()));
            }
            None => {}
        }

        let sled = self.sled.clone();
        // TODO: let remote_sled = self.remote_sled.clone();
        let aws = self.aws.clone();
        let accessed = self.accessed.clone();
        let remote = self.remote.clone();
        // Get the item from sled.
        let f = self.sled
            .get(key)
            .or_else(move |e| {
                trace!("get: unable to get key {} from sled layer: {:?}", key, e);
                // Get the item from remote sled.
                // TODO: remote_sled.get(key)
                futures::future::err(Error::new("remote sled layer not implemented"))
                    .or_else(move |e| {
                        trace!(
                            "get: unable to get key {} from remote sled layer: {:?}",
                            key,
                            e
                        );
                        // Get the item from AWS.
                        // If there's a thundering herd, God help our AWS bill.
                        aws.get(key)
                    })
                    .then(move |r| {
                        match r {
                            Ok(v) => {
                                // Set accessed item to writeback.
                                accessed
                                    .lock()
                                    .unwrap()
                                    .insert(key, AccessedItem::Writeback(v.clone()));
                                // Start async writeback.
                                remote
                                    .execute(sled.insert(v.clone(), 2).then(move |r| {
                                        if let Err(e) = r {
                                            warn!(
                                                "get: unable to persist key {} to sled layer: {:?}",
                                                key, e
                                            );
                                        }
                                        // Clear writeback accessed item.
                                        accessed.lock().unwrap().remove(&key);
                                        Ok(())
                                    }))
                                    .unwrap();
                                Ok(v)
                            }
                            Err(e) => {
                                trace!("get: unable to get key {} from aws layer: {:?}", key, e);
                                // Clear incoming accessed item.
                                accessed.lock().unwrap().remove(&key);
                                Err(Error::new("unable to get from any layer"))
                            }
                        }
                    })
            })
            // Why doesn't Box::new() work here?
            .into_box()
            .shared();
        accessed_guard.insert(key, AccessedItem::Incoming(f.clone()));
        Box::new(f.then(clone_shared))
    }

    fn insert(&self, value: Vec<u8>, expiry: u64) -> BoxFuture<()> {
        let key = ekiden_storage_base::hash_storage_key(&value);
        // Set accessed item to writeback.
        let mut accessed_guard = self.accessed.lock().unwrap();
        match accessed_guard.get(&key) {
            Some(&AccessedItem::Incoming(_)) => {
                trace!(
                    "insert: tried to insert key {} which is already Incoming. ignoring",
                    key
                );
                return Box::new(futures::future::ok(()));
            }
            Some(&AccessedItem::Writeback(_)) => {
                trace!(
                    "insert: tried to insert key {} which is already Writeback. ignoring",
                    key
                );
                return Box::new(futures::future::ok(()));
            }
            None => {}
        }
        accessed_guard.insert(key, AccessedItem::Writeback(value.clone()));
        let accessed = self.accessed.clone();
        self.remote
            .execute(self.sled.insert(value.clone(), expiry).then(move |r| {
                if let Err(e) = r {
                    warn!(
                        "insert: unable to persist key {} to sled layer: {:?}",
                        key, e
                    );
                }
                // Clear writeback accessed item.
                accessed.lock().unwrap().remove(&key);
                Ok(())
            }))
            .unwrap();
        self.remote
            .execute(self.aws.insert(value, expiry).or_else(move |e| {
                warn!(
                    "insert: unable to back up key {} to aws layer: {:?}",
                    key, e
                );
                Ok(())
            }))
            .unwrap();
        Box::new(futures::future::ok(()))
    }
}

fn di_factory(
    container: &mut ekiden_di::Container,
) -> ekiden_di::error::Result<Box<std::any::Any>> {
    let args = container.get_arguments().unwrap();
    let aws_region = value_t_or_exit!(
        args,
        "storage-rfc0004u-aws-region",
        rusoto_core::region::Region
    );
    let aws_table_name = args.value_of("storage-rfc0004u-aws-table-name")
        .unwrap()
        .to_string();
    let (init_tx, init_rx) = futures::sync::oneshot::channel();
    std::thread::spawn(|| match tokio_core::reactor::Core::new() {
        Ok(mut core) => {
            init_tx.send(Ok(core.remote())).unwrap();
            loop {
                core.turn(None);
            }
        }
        Err(e) => {
            init_tx.send(Err(e)).unwrap();
        }
    });
    use ekiden_di::error::ResultExt;
    let remote = init_rx
        .wait()
        .unwrap()
        .chain_err(|| "Couldn't create rector core")?;
    let sled = Arc::new(PersistentStorageBackend::new(
        Box::new(ekiden_epochtime::local::SystemTimeSource {}),
        "./",
    ).map_err(|e| {
        // Can't use chain_error because ekiden_common Error doesn't implement std Error.
        ekiden_di::error::Error::from(format!("Couldn't create sled layer: {:?}", e))
    })?);
    let aws = Arc::new(DynamoDbBackend::new(
        remote.clone(),
        aws_region,
        aws_table_name,
    ));
    let backend: Arc<StorageBackend> = Arc::new(Rfc0004UBackend::new(remote, sled, aws));
    Ok(Box::new(backend))
}

fn di_arg_aws_region<'a, 'b>() -> clap::Arg<'a, 'b> {
    clap::Arg::with_name("storage-rfc0004u-aws-region")
        .long("storage-rfc0004u-aws-region")
        .help("AWS region that the AWS layer of the RFC 0004 untrusted storage backend should use")
        .takes_value(true)
        .required(true)
}

fn di_arg_aws_table_name<'a, 'b>() -> clap::Arg<'a, 'b> {
    clap::Arg::with_name("storage-rfc0004u-aws-table-name")
        .long("storage-rfc0004u-aws-table-name")
        .help("DynamoDB table that the AWS layer of the RFC 0004 untrusted storage backend should use")
        .takes_value(true)
        .required(true)
}

// Register for dependency injection. This preparation starts a thread for the reactor core that
// runs forever.
create_component!(
    rfc0004u,
    "storage-backend",
    Rfc0004UBackend,
    StorageBackend,
    di_factory,
    [di_arg_aws_region(), di_arg_aws_table_name()]
);
