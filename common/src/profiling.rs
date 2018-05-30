//! Profiling helpers.
use std::time::Instant;

/// Guard for profiling a block of code.
pub struct ProfileGuard {
    crate_name: &'static str,
    function_name: &'static str,
    block_name: &'static str,
    start: Instant,
}

impl ProfileGuard {
    /// Create new profile guard.
    pub fn new(
        crate_name: &'static str,
        function_name: &'static str,
        block_name: &'static str,
    ) -> Self {
        ProfileGuard {
            crate_name: &crate_name,
            function_name: &function_name,
            block_name: &block_name,
            start: Instant::now(),
        }
    }

    /// Finalize profile guard and report results.
    fn finalize(&self) {
        let now = Instant::now();
        let duration = now.duration_since(self.start);

        if self.block_name.is_empty() {
            println!(
                "ekiden-profile:{}::{}={},{}",
                self.crate_name,
                self.function_name,
                duration.as_secs(),
                duration.subsec_nanos()
            );
        } else {
            println!(
                "ekiden-profile:{}::{}::{}={},{}",
                self.crate_name,
                self.function_name,
                self.block_name,
                duration.as_secs(),
                duration.subsec_nanos()
            );
        }
    }
}

impl Drop for ProfileGuard {
    fn drop(&mut self) {
        self.finalize();
    }
}

/// Profile a given block.
///
/// Results of profiling are output to stdout.
#[cfg(feature = "profiling")]
#[macro_export]
macro_rules! profile_block {
    ($block_name:expr) => {
        let name = {
            // Determine current function name.
            fn f() {}
            fn type_name_of<T>(_: T) -> &'static str {
                extern crate core;
                unsafe { core::intrinsics::type_name::<T>() }
            }
            let name = type_name_of(f);
            &name[6..name.len() - 4]
        };

        let _guard =
            $crate::profiling::ProfileGuard::new(env!("CARGO_PKG_NAME"), &name, &$block_name);
    };

    () => {
        profile_block!("");
    };
}

/// Profile a given block.
///
/// Results of profiling are output to stdout.
#[cfg(not(feature = "profiling"))]
#[macro_export]
macro_rules! profile_block {
    ($block_name:expr) => {};

    () => {};
}
