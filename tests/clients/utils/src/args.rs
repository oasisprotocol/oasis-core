use clap;

use ekiden_core::bytes::B256;

/// Determine contract identifier.
pub fn get_contract_id(args: &clap::ArgMatches) -> B256 {
    if args.is_present("test-contract-id") {
        value_t_or_exit!(args, "test-contract-id", B256)
    } else {
        value_t_or_exit!(args, "mr-enclave", B256)
    }
}
