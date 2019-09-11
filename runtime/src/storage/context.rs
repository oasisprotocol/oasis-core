//! Thread-local storage context.
//!
//! The storage context is a convenient way to share MKVS
//! implementations across the current thread.
use std::{cell::RefCell, mem::transmute, sync::Arc};

use super::{KeyValue, MKVS};

struct Ctx {
    mkvs: *mut dyn MKVS,
    untrusted_local: Arc<dyn KeyValue>,
}

thread_local! {
    static CTX: RefCell<Option<Ctx>> = RefCell::new(None);
}

struct CtxGuard {
    old_ctx: Option<Ctx>,
}

impl CtxGuard {
    fn new(mkvs: &mut dyn MKVS, untrusted_local: Arc<dyn KeyValue>) -> Self {
        let old_ctx = CTX.with(|ctx| {
            ctx.borrow_mut().replace(Ctx {
                // Need to fake the 'static lifetime on the trait. This is fine as we know
                // that the pointer can only actually be used while the StorageContext is
                // live.
                mkvs: unsafe { transmute::<&mut dyn MKVS, &'static mut dyn MKVS>(mkvs) },
                untrusted_local,
            })
        });

        CtxGuard { old_ctx }
    }
}

impl Drop for CtxGuard {
    fn drop(&mut self) {
        CTX.with(|local| {
            drop(local.replace(self.old_ctx.take()));
        });
    }
}

/// Thread-local storage context.
pub struct StorageContext;

impl StorageContext {
    /// Enter the storage context.
    pub fn enter<F, R>(mkvs: &mut dyn MKVS, untrusted_local: Arc<dyn KeyValue>, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _guard = CtxGuard::new(mkvs, untrusted_local);
        f()
    }

    /// Run a closure with the thread-local storage context.
    ///
    /// # Panics
    ///
    /// Will panic if called outside `StorageContext::enter`.
    pub fn with_current<F, R>(f: F) -> R
    where
        F: FnOnce(&mut dyn MKVS, &Arc<dyn KeyValue>) -> R,
    {
        CTX.with(|ctx| {
            let ctx = ctx.borrow();
            let ctx_ref = ctx.as_ref().expect("must only be called while entered");
            let mkvs_ref = unsafe { ctx_ref.mkvs.as_mut().expect("pointer is never null") };
            let untrusted_local_ref = ctx_ref.untrusted_local.clone();
            drop(ctx);

            f(mkvs_ref, &untrusted_local_ref)
        })
    }
}
