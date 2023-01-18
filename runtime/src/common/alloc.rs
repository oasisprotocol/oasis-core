//! A runtime memory allocation wrapper that handles OOMs.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    io::Write,
    sync::atomic::{AtomicUsize, Ordering::SeqCst},
};

/// A runtime memory allocation wrapper.
pub struct Allocator;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ret = System.alloc(layout);
        if ret.is_null() {
            // We are out of memory, make sure to at least signal that.
            eprintln!("Runtime memory allocation failed");
            let _ = std::io::stderr().flush();
        } else {
            // Record the amount of allocated memory.
            ALLOCATED.fetch_add(layout.size(), SeqCst);
        }
        ret
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        ALLOCATED.fetch_sub(layout.size(), SeqCst);
    }
}

/// Returns the amount of bytes currently allocated.
pub fn currently_allocated() -> usize {
    ALLOCATED.load(SeqCst)
}
