use std::{self, sync::Arc};

use super::{super::environment::Environment, future::Future};

/// Spawn a future in our environment and wait for its result.
pub fn block_on<F, R, E>(environment: Arc<Environment>, future: F) -> Result<R, E>
where
    F: Send + 'static + Future<Item = R, Error = E>,
    R: Send + 'static,
    E: Send + 'static,
{
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    environment.spawn(Box::new(future.then(move |result| {
        drop(result_tx.send(result));
        Ok(())
    })));
    result_rx
        .recv()
        .expect("block_on: Environment dropped our result sender")
}
