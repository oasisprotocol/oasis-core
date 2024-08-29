use honggfuzz::fuzz;

use oasis_core_runtime::common::sgx::pcs::Quote;

fn main() {
    loop {
        fuzz!(|quote: Vec<u8>| {
            let _ = Quote::parse(&quote);
        });
    }
}
