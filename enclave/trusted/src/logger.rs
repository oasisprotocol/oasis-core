#[cfg(target_env = "sgx")]
use ekiden_enclave_common::logger::EkidenLoggerRecord;

#[cfg(target_env = "sgx")]
use sgx_types::sgx_status_t;

/// EkidenLogger is an implementation of the Rust's log crate for the trusted environment
///
/// When a log message is sent, it makes OCALL to the logger in the untrusted part.
///
/// The scheme below illustrates this flow:
/// enclave: log::error!() --> EkidenLogger --> serialize log::Record --> untrusted_log() OCALL
/// untrusted: --> untrusted_log() OCALL --> deserialize log::Record --> logger().log()
///
/// # Examples
///
/// EkidenLogger is automatically registered when enclave is launched. To use it, call error, warn,
/// info, debug, or trace macros from the Rust's log crate, for example:
/// ```
/// extern crate log;
/// use log::{error, warn};
///
/// fn write_sth_to_log() {
///  let a = 404;
///
///  warn!("This is a warning {}!", a);
///  error!("And this is an error {}!", a);
/// }
/// ```
///
#[cfg(target_env = "sgx")]
pub struct EkidenLogger;

#[cfg(target_env = "sgx")]
pub static EKIDEN_LOGGER: EkidenLogger = EkidenLogger;

// For now, we relay all log messages from enclave to worker.
#[cfg(target_env = "sgx")]
pub const STATIC_MAX_LEVEL: log::Level = log::Level::Trace;

#[cfg(target_env = "sgx")]
impl log::Log for EkidenLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= STATIC_MAX_LEVEL
    }

    fn log(&self, record: &log::Record) {
        if !log::Log::enabled(self, record.metadata()) {
            return;
        }
        let elr = EkidenLoggerRecord {
            metadata_level: record.metadata().level(),
            metadata_target: record.metadata().target(),
            args: format!("{}", record.args()),
            module_path: record.module_path(),
            file: record.file(),
            line: record.line(),
        };

        let elr = serde_cbor::to_vec(&elr).unwrap();
        unsafe {
            untrusted_log(elr.as_ptr() as *const u8, elr.len()); // OCALL
        }
    }

    fn flush(&self) {}
}

#[cfg(target_env = "sgx")]
pub fn init() -> Result<(), log::SetLoggerError> {
    log::set_logger(&EKIDEN_LOGGER).map(|()| log::set_max_level(STATIC_MAX_LEVEL.to_level_filter()))
}

/// OCALL, see edl
#[cfg(target_env = "sgx")]
extern "C" {
    fn untrusted_log(record: *const u8, record_length: usize) -> sgx_status_t;
}
