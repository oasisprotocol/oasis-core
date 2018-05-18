//! Debug API service.
use std::sync::Arc;

use grpcio;
use grpcio::{RpcStatus, RpcStatusCode};

use ekiden_common::epochtime::local::LocalTimeSourceNotifier;
use ekiden_core::error::Result;
use ekiden_core::futures::Future;
use ekiden_node_dummy_api::{DummyDebug, SetEpochRequest, SetEpochResponse};

use super::backend::TimeSourceImpl;

struct DebugServiceInner {
    time_source: Arc<TimeSourceImpl>,
    time_notifier: Arc<LocalTimeSourceNotifier>,
}

#[derive(Clone)]
pub struct DebugService {
    inner: Arc<DebugServiceInner>,
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
            }),
        }
    }
}

impl DummyDebug for DebugService {
    fn set_epoch(
        &self,
        ctx: grpcio::RpcContext,
        request: SetEpochRequest,
        sink: grpcio::UnarySink<SetEpochResponse>,
    ) {
        let (ts, epoch_interval) = match *self.inner.time_source {
            TimeSourceImpl::MockRPC((ref ts, epoch_interval)) => (ts, epoch_interval),
            _ => {
                ctx.spawn(
                    sink.fail(RpcStatus::new(RpcStatusCode::Unimplemented, None))
                        .map_err(|_error| ()),
                );
                return;
            }
        };

        let epoch = request.get_epoch();
        match || -> Result<()> {
            ts.set_mock_time(epoch, epoch_interval)?;
            self.inner.time_notifier.notify_subscribers()?;
            Ok(())
        }()
        {
            Ok(_) => sink.success(SetEpochResponse::new()),
            Err(err) => sink.fail(RpcStatus::new(
                RpcStatusCode::Internal,
                Some(err.description().to_owned()),
            )),
        };
    }
}
