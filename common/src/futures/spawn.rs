pub use tokio::spawn;

use super::{
    killable::{self, KillHandle},
    Future,
};

/// Convenience method for combining `spawn` with `killable`.
pub fn spawn_killable<F>(f: F) -> KillHandle
where
    F: Future<Item = (), Error = ()> + 'static + Send,
{
    let (f, handle) = killable(f);
    spawn(f.map(|_| ()));

    handle
}
