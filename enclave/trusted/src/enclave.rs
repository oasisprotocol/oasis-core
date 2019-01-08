#[cfg(target_env = "sgx")]
use std;

#[cfg(target_env = "sgx")]
use logger;

/// ECALL, see edl
#[cfg(target_env = "sgx")]
#[no_mangle]
pub extern "C" fn enclave_late_init() {
    // Enable backtrace.
    if let Some(enclave_path) = std::enclave::get_enclave_path() {
        if let Err(e) =
            std::backtrace::enable_backtrace(enclave_path, std::backtrace::PrintFormat::Short)
        {
            println!("Couldn't enable backtrace: {}", e);
        }
    } else {
        println!("Couldn't enable backtrace: enclave path not available");
    }

    // Initialize ekiden logger for making OCALLs on log messages.
    match logger::init() {
        Ok(_) => (),
        Err(e) => println!("Unable to initialize ekiden logger: {}", e),
    };
}
