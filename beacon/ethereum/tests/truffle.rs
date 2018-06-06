extern crate ekiden_tools;

use ekiden_tools::truffle::{start_truffle, test_truffle};

#[test]
fn truffle() {
    let mut develop = start_truffle(env!("CARGO_MANIFEST_DIR"));

    test_truffle(env!("CARGO_MANIFEST_DIR"));

    let _ = develop.kill();
}
