extern crate ansi_term;
#[macro_use]
extern crate clap;
extern crate mktemp;

extern crate ekiden_tools;

use ansi_term::Colour::Red;
use clap::{App, Arg, SubCommand};
use std::process::exit;

use ekiden_tools::command_buildcontract::build_contract;
use ekiden_tools::command_shell::{cleanup_shell, shell};

fn main() {
    let matches = App::new("cargo")
        .subcommand(
            SubCommand::with_name("ekiden")
                .about(crate_description!())
                .author(crate_authors!())
                .version(crate_version!())
                .subcommand(
                    SubCommand::with_name("build-contract")
                        .about("Build an Ekiden contract")
                        .arg(
                            Arg::with_name("contract-crate")
                                .help("Name of the Cargo crate containing the contract")
                                .takes_value(true),
                        )
                        .arg(
                            Arg::with_name("version")
                                .help("Specify a version to build from crates.io")
                                .long("version")
                                .takes_value(true)
                                .conflicts_with("git")
                                .conflicts_with("path"),
                        )
                        .arg(
                            Arg::with_name("git")
                                .help("Git URL to build the specified crate from")
                                .long("git")
                                .takes_value(true)
                                .conflicts_with("version")
                                .conflicts_with("path"),
                        )
                        .arg(
                            Arg::with_name("branch")
                                .help("Branch to use when building from git")
                                .long("branch")
                                .takes_value(true)
                                .requires("git")
                                .conflicts_with("tag")
                                .conflicts_with("rev"),
                        )
                        .arg(
                            Arg::with_name("tag")
                                .help("Tag to use when building from git")
                                .long("tag")
                                .takes_value(true)
                                .requires("git")
                                .conflicts_with("branch")
                                .conflicts_with("rev"),
                        )
                        .arg(
                            Arg::with_name("rev")
                                .help("Specific commit to use when building from git")
                                .long("rev")
                                .takes_value(true)
                                .requires("git")
                                .conflicts_with("branch")
                                .conflicts_with("tag"),
                        )
                        .arg(
                            Arg::with_name("path")
                                .help("Filesystem path to local crate to build")
                                .long("path")
                                .takes_value(true)
                                .conflicts_with("version")
                                .conflicts_with("git"),
                        )
                        .arg(
                            Arg::with_name("cargo-addendum")
                                .help("Path of a file to append to the dummy top-level Cargo.toml")
                                .long("cargo-addendum")
                                .takes_value(true),
                        )
                        .arg(
                            Arg::with_name("release")
                                .long("release")
                                .help("Build contract in release mode, with optimizations"),
                        )
                        .arg(
                            Arg::with_name("sgx-mode")
                                .help("SGX mode")
                                .long("sgx-mode")
                                .takes_value(true)
                                .env("SGX_MODE")
                                .required(true),
                        )
                        .arg(
                            Arg::with_name("intel-sgx-sdk")
                                .help("Path to Intel SGX SDK")
                                .long("intel-sgx-sdk")
                                .takes_value(true)
                                .env("INTEL_SGX_SDK")
                                .required(true),
                        )
                        .arg(
                            Arg::with_name("sign-key")
                                .help(
                                    "Enclave signing key (if not specified, a default key is used)",
                                )
                                .long("sign-key")
                                .takes_value(true),
                        )
                        .arg(
                            Arg::with_name("output")
                                .help("Contract output directory")
                                .long("output")
                                .takes_value(true),
                        )
                        .arg(
                            Arg::with_name("output-identity")
                                .help("Should a contract identity file be generated")
                                .long("output-identity"),
                        )
                        .arg(
                            Arg::with_name("target-dir")
                                .help("Custom location to cache build artifacts")
                                .long("target-dir")
                                .takes_value(true),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("shell")
                        .about("Enter an Ekiden development environment")
                        .arg(
                            Arg::with_name("docker-shell")
                                .help("Shell to run within the docker environment")
                                .long("docker-shell")
                                .env("EKIDEN_DOCKER_SHELL")
                                .default_value("bash"),
                        )
                        .arg(
                            Arg::with_name("docker-image")
                                .help("Ekiden environment version to use")
                                .long("docker-image")
                                .env("EKIDEN_DOCKER_IMAGE")
                                .default_value("ekiden/development:0.1.0-alpha.4"),
                        )
                        .arg(
                            Arg::with_name("docker-name")
                                .help("Name for the docker environment")
                                .long("docker-name")
                                .takes_value(true)
                                .env("EKIDEN_DOCKER_NAME"),
                        )
                        .arg(
                            Arg::with_name("hardware")
                                .help("Enter a hardware backed rather than simulated environment")
                                .long("hw"),
                        )
                        .arg(
                            Arg::with_name("detach-keys")
                                .help("escape keys for exiting the Ekiden environment")
                                .long("detatch-keys")
                                .env("EKIDEN_DOCKER_DETACH_KEYS")
                                .default_value("ctrl-p,ctrl-q"),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("clean")
                        .about("Remove an Ekiden development environment")
                        .arg(
                            Arg::with_name("docker-name")
                                .help("Ekiden environment to remove")
                                .long("docker-name")
                                .takes_value(true)
                                .env("EKIDEN_DOCKER_NAME"),
                        )
                        .arg(
                            Arg::with_name("hardware")
                                .help("Enter a hardware backed rather than simulated environment")
                                .long("hw"),
                        ),
                ),
        )
        .get_matches();

    if let Some(ref ekiden_matches) = matches.subcommand_matches("ekiden") {
        let result = match ekiden_matches.subcommand() {
            ("build-contract", Some(build_args)) => build_contract(build_args),
            ("shell", Some(shell_args)) => shell(shell_args),
            ("clean", Some(clean_args)) => cleanup_shell(clean_args),
            _ => Err("no command specified".into()),
        };
        match result {
            Ok(_) => {}
            Err(error) => {
                println!("{} {}", Red.bold().paint("error:"), error);
                exit(128);
            }
        }
    }
}
