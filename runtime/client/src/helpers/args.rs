use clap;

use ekiden_core::bytes::B256;

/// Determine runtime identifier.
pub fn get_runtime_id(args: &clap::ArgMatches) -> B256 {
    if args.is_present("test-runtime-id") {
        value_t_or_exit!(args, "test-runtime-id", B256)
    } else {
        value_t_or_exit!(args, "mr-enclave", B256)
    }
}
