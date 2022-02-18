use std::path::Path;

use clap::{Arg, Command};

#[cfg(target_os = "linux")]
use oasis_core_runtime_loader::SgxsLoader;
use oasis_core_runtime_loader::{ElfLoader, Loader};

fn main() {
    let matches = Command::new("Oasis runtime loader")
        .arg(
            Arg::new("type")
                .long("type")
                .help("Runtime type")
                .possible_values(&["sgxs", "elf"])
                .takes_value(true)
                .default_value("sgxs"),
        )
        .arg(
            Arg::new("runtime")
                .value_name("RUNTIME")
                .help("Runtime filename")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::new("signature")
                .long("signature")
                .help("Signature filename")
                .takes_value(true),
        )
        .arg(
            Arg::new("host-socket")
                .long("host-socket")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    // Check if passed runtime exists.
    let filename = matches.value_of("runtime").unwrap().to_owned();
    assert!(
        Path::new(&filename).exists(),
        "Could not find runtime: {}",
        filename
    );

    // Decode arguments.
    let host_socket = matches
        .value_of_t::<String>("host-socket")
        .unwrap_or_else(|e| e.exit());
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
