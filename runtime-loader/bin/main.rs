#[macro_use]
extern crate clap;

use std::path::Path;

use clap::{App, Arg};

#[cfg(target_os = "linux")]
use oasis_core_runtime_loader::SgxsLoader;
use oasis_core_runtime_loader::{ElfLoader, Loader};

fn main() {
    let matches = App::new("Oasis runtime loader")
        .arg(
            Arg::with_name("type")
                .long("type")
                .help("Runtime type")
                .possible_values(&["sgxs", "elf"])
                .takes_value(true)
                .required(true)
                .default_value("sgxs"),
        )
        .arg(
            Arg::with_name("runtime")
                .value_name("RUNTIME")
                .help("Runtime filename")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("signature")
                .long("signature")
                .help("Signature filename")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("host-socket")
                .long("host-socket")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    // Check if passed runtime exists.
    let filename = matches.value_of("runtime").unwrap().to_owned();
    if !Path::new(&filename).exists() {
        panic!("Could not find runtime: {}", filename);
    }

    // Decode arguments.
    let host_socket = value_t!(matches, "host-socket", String).unwrap_or_else(|e| e.exit());
    let mode = matches.value_of("type").unwrap();
    let signature = matches.value_of("signature");

    // Create appropriate loader and run the runtime.
    let loader: Box<dyn Loader> = match mode {
        #[cfg(target_os = "linux")]
        "sgxs" => Box::new(SgxsLoader),
        #[cfg(not(target_os = "linux"))]
        "sgxs" => panic!("SGXS loader is only supported on Linux"),
        "elf" => Box::new(ElfLoader),
        _ => panic!("Invalid runtime type specified"),
    };
    loader
        .run(filename, signature, host_socket)
        .expect("runtime execution failed");
}
