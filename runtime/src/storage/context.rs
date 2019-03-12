//! Thread-local storage context.
//!
//! The storage context is a convenient way to share CAS and MKVS
//! implementations across the current thread.
use std::{cell::RefCell, sync::Arc};

use super::{CAS, MKVS};

struct Ctx {
    cas: Arc<CAS>,
    mkvs: *mut MKVS,
}

thread_local! {
    static CTX: RefCell<Option<Ctx>> = RefCell::new(None);
}

struct CtxGuard;

impl CtxGuard {
    fn new<M>(cas: Arc<CAS>, mkvs: &mut M) -> Self
    where
        M: MKVS + 'static,
    {
        CTX.with(|ctx| {
            assert!(ctx.borrow().is_none(), "nested enter is not allowed");
            ctx.borrow_mut().replace(Ctx { cas, mkvs });
        });

        CtxGuard
    }
}

impl Drop for CtxGuard {
    fn drop(&mut self) {
        CTX.with(|local| {
            drop(local.borrow_mut().take());
        });
    }
}

/// Thread-local storage context.
pub struct StorageContext;

impl StorageContext {
    /// Enter the storage context.
    pub fn enter<M, F, R>(cas: Arc<CAS>, mkvs: &mut M, f: F) -> R
    where
        M: MKVS + 'static,
        F: FnOnce() -> R,
    {
        let _guard = CtxGuard::new(cas, mkvs);
        f()
    }

    /// Run a closure with the thread-local storage context.
    ///
    /// # Panics
    ///
    /// Will panic if called outside `StorageContext::enter`.
    pub fn with_current<F, R>(f: F) -> R
    where
        F: FnOnce(&Arc<CAS>, &mut MKVS) -> R,
    {
        CTX.with(|ctx| {
            let ctx = ctx.borrow();
            let ctx_ref = ctx.as_ref().expect("must only be called while entered");
            let mkvs_ref = unsafe { ctx_ref.mkvs.as_mut().expect("pointer is never null") };

            f(&ctx_ref.cas, mkvs_ref)
        })
    }
}
