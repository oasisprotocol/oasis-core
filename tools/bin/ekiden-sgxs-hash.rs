//! A small utility to print the enclave hash.
extern crate ekiden_tools;

use std::env;

use ekiden_tools::sgxs;

fn main() {
    let mut args = env::args_os();
    let _name = args.next();
    let file = args.next();

    if let Some(file) = file {
        println!("{:?}", sgxs::get_enclave_hash(file).unwrap());
        return;
    }

    println!("Usage: ekiden-sgxs-hash <file>");
}
