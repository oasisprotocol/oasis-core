use std::path::Path;

use clap::{Arg, Command};

use oasis_core_runtime_loader::Loader;
#[cfg(target_os = "linux")]
use oasis_core_runtime_loader::SgxsLoader;

fn main() {
    let matches = Command::new("Oasis Core Runtime Loader")
        .arg(
            Arg::new("type")
                .long("type")
                .help("Runtime type")
                .value_parser(["sgxs"])
                .default_value("sgxs"),
        )
        .arg(
            Arg::new("runtime")
                .value_name("RUNTIME")
                .help("Runtime filename")
                .required(true),
        )
        .arg(
            Arg::new("signature")
                .long("signature")
                .help("Signature filename"),
        )
        .arg(Arg::new("host-socket").long("host-socket").required(true))
        .get_matches();

    // Check if passed runtime exists.
    let filename = matches.get_one::<String>("runtime").unwrap();
    assert!(
        Path::new(filename).exists(),
        "Could not find runtime: {}",
        filename
    );

    // Decode arguments.
    let host_socket = matches.get_one::<String>("host-socket").unwrap();
    let mode = matches.get_one::<String>("type").unwrap();
    let signature = matches
        .get_one::<String>("signature")
        .map(|sig| sig.as_ref());

    // Create appropriate loader and run the runtime.
    let loader: Box<dyn Loader> = match mode.as_ref() {
        #[cfg(target_os = "linux")]
        "sgxs" => Box::new(SgxsLoader),
        #[cfg(not(target_os = "linux"))]
        "sgxs" => panic!("SGXS loader is only supported on Linux"),
        _ => panic!("Invalid runtime type specified"),
    };
    loader
        .run(filename, signature, host_socket)
        .expect("runtime execution failed");
}
