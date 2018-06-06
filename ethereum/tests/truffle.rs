extern crate ekiden_ethereum;
#[macro_use(defer)]
extern crate scopeguard;

use ekiden_ethereum::truffle::{start_truffle, test_truffle};

#[test]
fn truffle() {
    let mut develop = start_truffle(env!("CARGO_MANIFEST_DIR"));
    defer! {{
        let _ = develop.kill();
    }};

    test_truffle(env!("CARGO_MANIFEST_DIR"));
}
