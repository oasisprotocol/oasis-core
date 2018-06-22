//! Debug API service.
use std::sync::Arc;
use std::time::Duration;

use grpcio;
use grpcio::RpcStatus;
use grpcio::RpcStatusCode::Internal;

use ekiden_core::environment::Environment;
use ekiden_core::error::{Error, Result};
use ekiden_core::futures::{future, Future, Stream};
use ekiden_epochtime::interface::{EpochTime, TimeSource};
use ekiden_epochtime::local::{LocalTimeSourceNotifier, MockTimeSource};
use ekiden_node_dummy_api::{DummyDebug, SetEpochRequest, SetEpochResponse};

use futures_timer::Interval;

struct DebugServiceInner {
    environment: Arc<Environment>,
    time_source: Arc<MockTimeSource>,
    time_notifier: Arc<LocalTimeSourceNotifier>,
}

#[derive(Clone)]
pub struct DebugService {
    inner: Arc<DebugServiceInner>,
}

macro_rules! invalid {
    ($sink:ident, $code:ident, $e:expr) => {
        $sink.fail(RpcStatus::new($code, Some($e.description().to_owned())))
    };
}

impl DebugService {
    /// Create new debug server instance.
    pub fn new(
        environment: Arc<Environment>,
        time_source: Arc<MockTimeSource>,
        time_notifier: Arc<LocalTimeSourceNotifier>,
    ) -> Self {
        DebugService {
            inner: Arc::new(DebugServiceInner {
                environment,
                time_source,
                time_notifier,
            }),
        }
    }

    fn checked_set_mock_time(&self, epoch: EpochTime) -> Result<()> {
        let time_source = self.inner.time_source.clone();
        // The MockTimeSource set_mock_time routine does no sanity checking
        // at all, by design.  Ensure that time is moving forward, since the
        // notify routine will fail if time advances backwards.
        if time_source.get_epoch().unwrap().0 >= epoch {
            return Err(Error::new("New epoch does not advance time"));
        }

        trace!("MockTime: (On RPC) Epoch: {}", epoch);

        time_source.set_mock_epoch(epoch)?;

        // In Mock-wiating state, we may need to start a timer:
        let (waiting, epoch_interval) = time_source.was_waiting()?;
        if waiting {
            trace!("MockTime: Starting timer.");

            let dur = Duration::from_secs(epoch_interval);
            self.inner.environment.spawn({
                let time_source = time_source.clone();
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
        }
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
        let epoch = request.get_epoch();
        match self.checked_set_mock_time(epoch) {
            Ok(_) => ctx.spawn(sink.success(SetEpochResponse::new()).map_err(|_error| ())),
            Err(err) => ctx.spawn(invalid!(sink, Internal, err).map_err(|_error| ())),
        };
    }
}
