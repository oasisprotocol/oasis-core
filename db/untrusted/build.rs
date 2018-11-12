extern crate ekiden_tools;

fn main() {
    ekiden_tools::detect_sgx_features();
    ekiden_tools::find_untrusted_libs();
}
