//! Debug API service.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use grpcio;
use grpcio::RpcStatus;
use grpcio::RpcStatusCode::{Internal, Unimplemented};

use ekiden_common::epochtime::{EpochTime, TimeSource};
use ekiden_common::epochtime::local::{LocalTimeSourceNotifier, MockTimeSource};
use ekiden_core::error::{Error, Result};
use ekiden_core::futures::{future, Future, Stream};
use ekiden_node_dummy_api::{DummyDebug, SetEpochRequest, SetEpochResponse};

use futures_timer::Interval;

use super::backend::TimeSourceImpl;

struct DebugServiceInner {
    time_source: Arc<TimeSourceImpl>,
    time_notifier: Arc<LocalTimeSourceNotifier>,
    mock_time_started: Mutex<bool>,
}

#[derive(Clone)]
pub struct DebugService {
    inner: Arc<DebugServiceInner>,
}

macro_rules! invalid {
    ($sink:ident,$code:ident,$e:expr) => {
        $sink.fail(RpcStatus::new(
            $code,
            Some($e.description().to_owned()),
        ))
    }
}

impl DebugService {
    /// Create new debug server instance.
    pub fn new(
        time_source: Arc<TimeSourceImpl>,
        time_notifier: Arc<LocalTimeSourceNotifier>,
    ) -> Self {
        DebugService {
            inner: Arc::new(DebugServiceInner {
                time_source,
                time_notifier,
                mock_time_started: Mutex::new(false),
            }),
        }
    }

    fn checked_set_mock_time(
        &self,
        time_source: &MockTimeSource,
        epoch: EpochTime,
        epoch_interval: u64,
    ) -> Result<()> {
        // The MockTimeSource set_mock_time routine does no sanity checking
        // at all, by design.  Ensure that time is moving forward, since the
        // notify routine will fail if time advances backwards.
        if time_source.get_epoch().unwrap().0 >= epoch {
            return Err(Error::new("New epoch does not advance time"));
        }

        trace!(
            "MockTime: (On RPC) Epoch: {}, Till: {}",
            epoch,
            epoch_interval
        );

        time_source.set_mock_time(epoch, epoch_interval)?;
        self.inner.time_notifier.notify_subscribers()?;
        Ok(())
    }
}

impl DummyDebug for DebugService {
    fn set_epoch(
        &self,
        ctx: grpcio::RpcContext,
        request: SetEpochRequest,
        sink: grpcio::UnarySink<SetEpochResponse>,
    ) {
        match *self.inner.time_source {
            TimeSourceImpl::MockRPC((ref ts, epoch_interval)) => {
                let epoch = request.get_epoch();
                match self.checked_set_mock_time(ts, epoch, epoch_interval) {
                    Ok(_) => ctx.spawn(sink.success(SetEpochResponse::new()).map_err(|_error| ())),
                    Err(err) => ctx.spawn(invalid!(sink, Internal, err).map_err(|_error| ())),
                };
            }
            TimeSourceImpl::Mock((ref ts, epoch_interval, wait_on_rpc)) => {
                let mut mock_time_started = self.inner.mock_time_started.lock().unwrap();

                if !wait_on_rpc || *mock_time_started {
                    error!("MockTime: Unexpected RPC call.");
                    ctx.spawn(
                        sink.fail(RpcStatus::new(Unimplemented, None))
                            .map_err(|_error| ()),
                    );
                    return;
                }

                let epoch = request.get_epoch();
                match self.checked_set_mock_time(ts, epoch, epoch_interval) {
                    Ok(_) => {
                        trace!("MockTime: Starting timer.");
                        let dur = Duration::from_secs(epoch_interval);
                        ctx.spawn({
                            let time_source = ts.clone();
                            let time_notifier = self.inner.time_notifier.clone();

                            Box::new(
                                Interval::new(dur)
                                    .map_err(|error| Error::from(error))
                                    .for_each(move |_| {
                                        let (now, till) = time_source.get_epoch().unwrap();
                                        trace!("MockTime: Epoch: {} Till: {}", now + 1, till);
                                        time_source.set_mock_time(now + 1, till)?;
                                        time_notifier.notify_subscribers()
                                    })
                                    .then(|_| future::ok(())),
                            )
                        });

                        *mock_time_started = true;

                        ctx.spawn(sink.success(SetEpochResponse::new()).map_err(|_error| ()));
                    }
                    Err(err) => ctx.spawn(invalid!(sink, Internal, err).map_err(|_error| ())),
                }
            }
            _ => {
                ctx.spawn(
                    sink.fail(RpcStatus::new(Unimplemented, None))
                        .map_err(|_error| ()),
                );
            }
        }
    }
}
